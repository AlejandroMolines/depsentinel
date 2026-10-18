package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/allowlist"
	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/config"
	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/engine"
	"github.com/AlejandroMolines/depsentinel/internal/fix"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/registry"
	"github.com/AlejandroMolines/depsentinel/internal/report"
	"github.com/AlejandroMolines/depsentinel/internal/scanner"
	"github.com/AlejandroMolines/depsentinel/internal/version"
)

const workflowTemplate = `name: DepSentinel
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 5 * * 1" # cada lunes: detecta avisos nuevos aunque no cambie el código

permissions:
  contents: read
  pull-requests: write # para comentar el resultado en el PR

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Consejo: fija las acciones a un SHA de commit (depsentinel fix lo hace por ti).
      - uses: AlejandroMolines/depsentinel/action@v1
        with:
          fail-on: high
`

// ---------- init ----------

func (a *App) cmdInit(args []string) error {
	fs := newFlagSet("init", a.Stderr, "[ruta] [opciones]")
	force := fs.Bool("force", false, "sobrescribe .depsentinel.json si ya existe")
	workflow := fs.Bool("workflow", false, "crea también .github/workflows/depsentinel.yml")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	} else if len(pos) > 1 {
		return usageErr("too many arguments: %v", pos[1:])
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return usageErr("%s is not a directory", dir)
	}
	cfgPath := filepath.Join(dir, config.FileName)
	cfg := config.Default()
	if _, err := os.Stat(cfgPath); err == nil && !*force {
		fmt.Fprintf(a.Stdout, "Already exists %s (use --force to overwrite).\n", cfgPath)
	} else {
		if err := cfg.Save(cfgPath); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "Created %s\n", cfgPath)
	}
	alPath := filepath.Join(dir, cfg.AllowlistFile)
	if _, err := os.Stat(alPath); err != nil {
		l := &allowlist.List{Path: alPath}
		if err := l.Save(); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "Created %s (empty allowlist: every exception requires a justification)\n", alPath)
	}
	if *workflow {
		wf := filepath.Join(dir, ".github", "workflows", "depsentinel.yml")
		if _, err := os.Stat(wf); err == nil && !*force {
			fmt.Fprintf(a.Stdout, "Already exists %s\n", wf)
		} else {
			if err := os.MkdirAll(filepath.Dir(wf), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(wf, []byte(workflowTemplate), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "Created %s\n", wf)
		}
	}
	files, err := scanner.Detect(dir, cfg.IgnorePaths)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "\nManifests detected:")
	found := false
	for _, eco := range model.AllEcosystems {
		if len(files[eco]) > 0 {
			found = true
			fmt.Fprintf(a.Stdout, "  %-15s %s\n", eco.Label(), strings.Join(files[eco], ", "))
		}
	}
	if !found {
		fmt.Fprintln(a.Stdout, "  (none yet)")
	}
	fmt.Fprintln(a.Stdout, "\nNext step:  depsentinel scan")
	return nil
}

// ---------- fix ----------

func (a *App) cmdFix(ctx context.Context, args []string) error {
	fs := newFlagSet("fix", a.Stderr, "[ruta] [opciones]\n\nSube las dependencias directas vulnerables y fija las acciones de GitHub a un SHA.\nModifica ficheros del proyecto: revisa el resultado con git diff.")
	f := scanFlags{format: "table", minSev: "low", ecosystem: "auto"}
	dry := fs.Bool("dry-run", false, "muestra el plan sin modificar ningún fichero")
	fs.StringVar(&f.ecosystem, "ecosystem", "auto", "ecosistemas a analizar")
	fs.StringVar(&f.ecosystem, "e", "auto", "alias de --ecosystem")
	fs.StringVar(&f.lock, "lock", "", "lockfile de npm a usar")
	fs.BoolVar(&f.offline, "offline", false, "sin red (no se pueden calcular arreglos que dependan de OSV)")
	fs.StringVar(&f.configPath, "config", "", "ruta de .depsentinel.json")
	fs.BoolVar(&f.quiet, "quiet", false, "no muestra el progreso")
	fs.BoolVar(&f.prodOnly, "prod-only", false, "ignora las dependencias de desarrollo")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	} else if len(pos) > 1 {
		return usageErr("too many arguments: %v", pos[1:])
	}
	setup, err := a.prepare(&f, dir, false)
	if err != nil {
		return err
	}
	res, err := engine.Scan(ctx, setup.opts)
	if err != nil {
		return err
	}
	var gh *registry.GitHub
	if !setup.opts.Offline {
		h := httpx.New(time.Duration(setup.cfg.Network.TimeoutSeconds)*time.Second, false)
		gh = registry.NewGitHub(h, setup.opts.Endpoints.GitHub)
	}
	plan, err := fix.BuildPlan(ctx, fix.Options{BaseDir: res.Inventory.BaseDir, GitHub: gh}, res)
	if err != nil {
		return err
	}
	if *dry {
		plan.Preview(a.Stdout, true)
		return nil
	}
	changed, err := plan.Apply(res.Inventory.BaseDir)
	if err != nil {
		return fmt.Errorf("no se pudo aplicar el arreglo: %w", err)
	}
	plan.Preview(a.Stdout, false)
	if len(changed) > 0 {
		fmt.Fprintf(a.Stdout, "Ficheros modificados: %s\n", strings.Join(changed, ", "))
		for _, c := range changed {
			if filepath.Base(c) == "package.json" {
				fmt.Fprintln(a.Stdout, "Next step: npm install (regenerates the lockfile) and run depsentinel scan again.")
				break
			}
		}
	}
	return nil
}

// ---------- allowlist ----------

func (a *App) allowlistPath(dir, cfgFlag string) (string, *config.Config, error) {
	cfgPath := cfgFlag
	if cfgPath == "" {
		cfgPath = config.Find(dir)
	}
	cfg := config.Default()
	base := dir
	if cfgPath != "" {
		c, err := config.Load(cfgPath)
		if err != nil {
			return "", nil, usageErr("invalid configuration: %v", err)
		}
		cfg, base = c, filepath.Dir(cfgPath)
	}
	p := cfg.AllowlistFile
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	return p, cfg, nil
}

func splitNameVersion(arg string) (string, string) {
	if i := strings.LastIndex(arg, "@"); i > 0 {
		return arg[:i], arg[i+1:]
	}
	return arg, ""
}

func (a *App) cmdAllowlist(args []string) error {
	if len(args) == 0 {
		return usageErr("uso: depsentinel allowlist <add|list|remove> ...")
	}
	sub, rest := args[0], args[1:]
	fs := newFlagSet("allowlist "+sub, a.Stderr, "[paquete[@versión]] [opciones]")
	dir := fs.String("dir", ".", "directorio del proyecto")
	cfgFlag := fs.String("config", "", "ruta de .depsentinel.json")
	eco := fs.String("ecosystem", "", "ecosistema (npm, pypi, go, docker, actions); por defecto cualquiera")
	ver := fs.String("version", "", "versión concreta (por defecto todas)")
	rule := fs.String("rule", "", "regla concreta, p. ej. typosquat (por defecto todas salvo malicious)")
	reason := fs.String("reason", "", "REQUIRED justification: why it is safe to ignore this finding")
	expires := fs.String("expires", "", "caducidad AAAA-MM-DD (recomendado)")
	pos, err := parseInterspersed(fs, rest)
	if err != nil {
		return err
	}
	path, _, err := a.allowlistPath(*dir, *cfgFlag)
	if err != nil {
		return err
	}
	l, err := allowlist.Load(path)
	if err != nil {
		return usageErr("invalid allowlist: %v", err)
	}
	switch sub {
	case "list":
		if len(l.Entries) == 0 {
			fmt.Fprintf(a.Stdout, "Allowlist is empty (%s).\n", path)
			return nil
		}
		tw := tabwriter.NewWriter(a.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ECOSISTEMA\tPAQUETE\tVERSIÓN\tREGLA\tCADUCA\tMOTIVO")
		for _, e := range l.Entries {
			v, r, x := e.Version, e.Rule, e.Expires
			if v == "" {
				v = "*"
			}
			if r == "" {
				r = "*"
			}
			if x == "" {
				x = "nunca"
			} else if e.Expired(time.Now()) {
				x += " (caducada)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.Ecosystem, e.Name, v, r, x, e.Reason)
		}
		return tw.Flush()
	case "add", "remove", "rm":
		if len(pos) != 1 {
			return usageErr("uso: depsentinel allowlist %s <paquete[@versión]> [opciones]", sub)
		}
		name, v := splitNameVersion(pos[0])
		if v != "" && *ver != "" && v != *ver {
			return usageErr("la versión indicada en el nombre (%s) y en --version (%s) no coinciden", v, *ver)
		}
		if v == "" {
			v = *ver
		}
		if *eco != "" && *eco != "*" {
			e, ok := model.ParseEcosystem(*eco)
			if !ok {
				return usageErr("unknown ecosystem %q", *eco)
			}
			*eco = string(e)
		}
		if *rule != "" && *rule != "*" {
			known := false
			for _, r := range config.KnownRules {
				if r == *rule {
					known = true
				}
			}
			if !known && !strings.HasPrefix(*rule, "GHSA-") && !strings.HasPrefix(*rule, "CVE-") && !strings.HasPrefix(*rule, "DS-") && !strings.HasPrefix(*rule, "MAL-") {
				return usageErr("unknown rule %q (rules: %s; you can also use an advisory ID, e.g. GHSA-…)", *rule, strings.Join(config.SortedRules(), ", "))
			}
		}
		if sub == "add" {
			e := allowlist.Entry{Ecosystem: *eco, Name: name, Version: v, Rule: *rule, Reason: strings.TrimSpace(*reason), Added: time.Now().Format("2006-01-02"), Expires: *expires}
			if err := l.Add(e); err != nil {
				return usageErr("%v", err)
			}
			if err := l.Save(); err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "Añadido a %s: %s", path, name)
			if v != "" {
				fmt.Fprintf(a.Stdout, "@%s", v)
			}
			fmt.Fprintf(a.Stdout, "\n  motivo: %s\n", e.Reason)
			if *eco == "" {
				fmt.Fprintln(a.Stdout, "  (vale para cualquier ecosistema; usa --ecosystem para acotarlo)")
			}
			fmt.Fprintln(a.Stdout, "Haz commit de ese fichero para que lo vea el equipo y el CI.")
			return nil
		}
		n := l.Remove(name, *eco, v, *rule)
		if n == 0 {
			return usageErr("no hay ninguna excepción para %s", pos[0])
		}
		if err := l.Save(); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "Eliminadas %d excepción(es) de %s\n", n, name)
		return nil
	}
	return usageErr("subcomando desconocido %q (usa add, list o remove)", sub)
}

// ---------- sbom ----------

func (a *App) cmdSBOM(args []string) error {
	fs := newFlagSet("sbom", a.Stderr, "[ruta] [opciones]")
	format := fs.String("format", "cyclonedx", "formato del SBOM (cyclonedx)")
	output := fs.String("output", "", "fichero de salida (por defecto la salida estándar)")
	fs.StringVar(output, "o", "", "alias de --output")
	eco := fs.String("ecosystem", "auto", "ecosistemas a incluir")
	lock := fs.String("lock", "", "lockfile de npm a usar")
	prod := fs.Bool("prod-only", false, "excluye las dependencias de desarrollo")
	cfgFlag := fs.String("config", "", "ruta de .depsentinel.json")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if !strings.EqualFold(*format, "cyclonedx") {
		return usageErr("formato de SBOM no soportado %q (usa cyclonedx)", *format)
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	} else if len(pos) > 1 {
		return usageErr("too many arguments: %v", pos[1:])
	}
	f := scanFlags{format: "table", minSev: "low", ecosystem: *eco, lock: *lock, prodOnly: *prod, configPath: *cfgFlag, quiet: true}
	setup, err := a.prepare(&f, dir, false)
	if err != nil {
		return err
	}
	inv, err := engine.BuildInventory(setup.opts)
	if err != nil {
		return err
	}
	if len(inv.Packages) == 0 {
		return usageErr("no se encontraron dependencias en %s", dir)
	}
	name := inv.RootName
	if name == "" {
		abs, _ := filepath.Abs(inv.BaseDir)
		name = filepath.Base(abs)
	}
	data, err := report.CycloneDX(inv.Packages, report.SBOMOptions{RootName: name, RootVersion: inv.RootVersion, Now: time.Now(), ToolVersion: version.Version})
	if err != nil {
		return err
	}
	for _, w := range inv.Warnings {
		fmt.Fprintf(a.Stderr, "aviso: %s\n", w)
	}
	if *output == "" {
		_, err = a.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "SBOM CycloneDX con %d componentes escrito en %s\n", len(inv.Packages), *output)
	return nil
}

// ---------- report ----------

func (a *App) cmdReport(ctx context.Context, args []string) error {
	fs := newFlagSet("report", a.Stderr, "[ruta] [opciones]\n\nGenera el panel HTML de un escaneo nuevo o de un informe JSON existente (--input).")
	var f scanFlags
	f.register(fs, false)
	fs.Bool("html", true, "genera el panel HTML (es el único formato)")
	open := fs.Bool("open", false, "abre el informe en el navegador")
	input := fs.String("input", "", "usa este informe JSON (de scan --format json) en lugar de escanear")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	out := f.output
	if out == "" {
		out = "depsentinel-report.html"
	}
	var html []byte
	if *input != "" {
		raw, err := os.ReadFile(*input)
		if err != nil {
			return err
		}
		if html, err = report.HTMLFromJSON(raw); err != nil {
			return err
		}
	} else {
		dir := "."
		if len(pos) == 1 {
			dir = pos[0]
		} else if len(pos) > 1 {
			return usageErr("too many arguments: %v", pos[1:])
		}
		setup, err := a.prepare(&f, dir, false)
		if err != nil {
			return err
		}
		res, err := engine.Scan(ctx, setup.opts)
		if err != nil {
			return err
		}
		if html, err = report.HTML(res.Report); err != nil {
			return err
		}
	}
	if err := os.WriteFile(out, html, 0o644); err != nil {
		return err
	}
	abs, _ := filepath.Abs(out)
	fmt.Fprintf(a.Stdout, "Informe escrito en %s\n", abs)
	if *open {
		if err := openBrowser(abs); err != nil {
			fmt.Fprintf(a.Stderr, "aviso: no pude abrir el navegador: %v\n", err)
		}
	}
	return nil
}

// ---------- db ----------

func (a *App) cmdDB(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageErr("uso: depsentinel db <update|status|clean>")
	}
	sub, rest := args[0], args[1:]
	fs := newFlagSet("db "+sub, a.Stderr, "[opciones]")
	feed := fs.String("feed-url", "", "URL del feed (por defecto el del repositorio o feed_url de la configuración)")
	pubkey := fs.String("pubkey", "", "clave pública Ed25519 (base64) para verificar la firma")
	unsigned := fs.Bool("allow-unsigned", false, "acepta un feed sin firma verificada (no recomendado)")
	cfgFlag := fs.String("config", "", "ruta de .depsentinel.json")
	all := fs.Bool("all", false, "clean: borra también el feed descargado")
	if _, err := parseInterspersed(fs, rest); err != nil {
		return err
	}
	cfg := config.Default()
	cfgPath := *cfgFlag
	if cfgPath == "" {
		cfgPath = config.Find(".")
	}
	if cfgPath != "" {
		c, err := config.Load(cfgPath)
		if err != nil {
			return usageErr("invalid configuration: %v", err)
		}
		cfg = c
	}
	cch := cache.Default()
	switch sub {
	case "update":
		url := firstNonEmpty(*feed, os.Getenv("DEPSENTINEL_FEED_URL"), cfg.FeedURL, db.DefaultFeedURL)
		key := firstNonEmpty(*pubkey, cfg.FeedPublicKey)
		h := httpx.New(time.Duration(cfg.Network.TimeoutSeconds)*time.Second, os.Getenv("DEPSENTINEL_OFFLINE") != "")
		fmt.Fprintf(a.Stderr, "→ Descargando feed de %s…\n", url)
		res, err := db.Update(ctx, db.UpdateOptions{FeedURL: url, PublicKey: key, AllowUnsigned: *unsigned, CacheDir: cch.Dir(), HTTP: h, Now: time.Now()})
		if err != nil {
			return &exitError{code: ExitIncomplete, msg: "no se pudo actualizar la base de datos: " + err.Error()}
		}
		sig := "firma verificada"
		if !res.Signed {
			sig = "SIN verificar la firma"
		}
		fmt.Fprintf(a.Stdout, "Base de datos actualizada: versión %s (%s)\n  ficheros: %s\n", res.Version, sig, strings.Join(res.Files, ", "))
		return nil
	case "status":
		s, err := db.Load(cch.Dir())
		if err != nil {
			return err
		}
		info := s.Info()
		fmt.Fprintf(a.Stdout, "Caché:               %s\n", cch.Dir())
		fmt.Fprintf(a.Stdout, "Semilla embebida:    %s (%d paquetes maliciosos o comprometidos en total)\n", info.SeedUpdated, info.MaliciousEntries)
		if info.Feed != nil {
			age := int(time.Since(info.Feed.Checked).Hours() / 24)
			sig := "firmado"
			if !info.Feed.Signed {
				sig = "sin firma verificada"
			}
			fmt.Fprintf(a.Stdout, "Feed descargado:     versión %s, %s, hace %d días (%s)\n", info.Feed.Version, sig, age, info.Feed.Source)
			if age > 14 {
				fmt.Fprintln(a.Stdout, "  ⚠ El feed tiene más de 14 días: ejecuta depsentinel db update (o prográmalo con cron).")
			}
		} else {
			fmt.Fprintln(a.Stdout, "Feed descargado:     ninguno (se usa solo la semilla). Ejecuta: depsentinel db update")
		}
		for _, eco := range model.AllEcosystems {
			if n := info.Popular[string(eco)]; n > 0 {
				fmt.Fprintf(a.Stdout, "Nombres populares:   %-8s %d\n", eco, n)
			}
		}
		return nil
	case "clean":
		ns := []string{"osv", "npm", "pypi", "goproxy"}
		if *all {
			ns = append(ns, "feed")
		}
		if err := cch.ClearNamespaces(ns...); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "Caché limpiada (%s)\n", strings.Join(ns, ", "))
		return nil
	}
	return usageErr("subcomando desconocido %q (usa update, status o clean)", sub)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
