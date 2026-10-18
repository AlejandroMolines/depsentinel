package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/allowlist"
	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/config"
	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/engine"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/report"
	"github.com/AlejandroMolines/depsentinel/internal/term"
)

// scanFlags son las opciones comunes a scan, audit y report.
type scanFlags struct {
	ecosystem  string
	lock       string
	format     string
	output     string
	ci         bool
	failOn     string
	only       string
	minSev     string
	offline    bool
	noRegistry bool
	noOSV      bool
	deep       bool
	prodOnly   bool
	configPath string
	noColor    bool
	quiet      bool
	strict     bool
	showAllow  bool
	outMD      string
	outHTML    string
}

func (f *scanFlags) register(fs interface {
	StringVar(*string, string, string, string)
	BoolVar(*bool, string, bool, string)
}, audit bool) {
	fs.StringVar(&f.ecosystem, "ecosystem", "auto", "ecosystems to analyze: auto or list (npm,pypi,go,docker,actions)")
	fs.StringVar(&f.ecosystem, "e", "auto", "alias of --ecosystem")
	fs.StringVar(&f.lock, "lock", "", "npm lockfile to use instead of auto-detecting (e.g. package-lock.json)")
	fs.StringVar(&f.format, "format", "table", "output format: table, json, markdown, github")
	fs.StringVar(&f.format, "f", "table", "alias of --format")
	fs.StringVar(&f.output, "output", "", "write the result to this file instead of stdout")
	fs.StringVar(&f.output, "o", "", "alias of --output")
	fs.BoolVar(&f.ci, "ci", false, "CI mode: no colors, GitHub annotations and fail if risk >= --fail-on (default high)")
	fs.StringVar(&f.failOn, "fail-on", "", "minimum severity that fails the command: low, medium, high, critical or none")
	defOnly := ""
	if audit {
		defOnly = "high,critical"
	}
	fs.StringVar(&f.only, "only", defOnly, "show only these severities (e.g. high,critical)")
	fs.StringVar(&f.minSev, "min-severity", "low", "hide findings below this severity")
	fs.BoolVar(&f.offline, "offline", false, "no network: local rules only")
	fs.BoolVar(&f.noRegistry, "no-registry", false, "do not query registries (npm, PyPI, Go proxy)")
	fs.BoolVar(&f.noOSV, "no-osv", false, "do not query OSV")
	fs.BoolVar(&f.deep, "deep", false, "download and inspect npm packages with install scripts (slower)")
	fs.BoolVar(&f.prodOnly, "prod-only", false, "ignore development dependencies")
	fs.StringVar(&f.configPath, "config", "", "path to .depsentinel.json (searched in the project by default)")
	fs.BoolVar(&f.noColor, "no-color", false, "disable colors")
	fs.BoolVar(&f.quiet, "quiet", false, "hide progress")
	fs.BoolVar(&f.quiet, "q", false, "alias of --quiet")
	fs.BoolVar(&f.strict, "strict", false, "fail (code 3) if a data source was unavailable")
	fs.BoolVar(&f.showAllow, "show-allowed", false, "include allowlisted findings in the output")
	fs.StringVar(&f.outMD, "output-markdown", "", "also write the PR comment (Markdown) to this file")
	fs.StringVar(&f.outHTML, "output-html", "", "also write the HTML panel to this file")
}

type scanSetup struct {
	opts     engine.Options
	failOn   model.Severity
	only     []model.Severity
	minSev   model.Severity
	palette  term.Palette
	cfg      *config.Config
	ecoFlag  bool
	progress bool
}

func (a *App) prepare(f *scanFlags, dir string, ciDefault bool) (*scanSetup, error) {
	cfgPath := f.configPath
	if cfgPath == "" {
		cfgPath = config.Find(dir)
	}
	cfg := config.Default()
	if cfgPath != "" {
		c, err := config.Load(cfgPath)
		if err != nil {
			return nil, usageErr("invalid configuration: %v", err)
		}
		cfg = c
	} else if f.configPath != "" {
		return nil, usageErr("no existe el fichero de configuración %s", f.configPath)
	}
	setup := &scanSetup{cfg: cfg}

	var ecos []model.Ecosystem
	if f.ecosystem != "" && !strings.EqualFold(f.ecosystem, "auto") && !strings.EqualFold(f.ecosystem, "all") {
		for _, s := range splitCSV(f.ecosystem) {
			e, ok := model.ParseEcosystem(s)
			if !ok {
				return nil, usageErr("unknown ecosystem %q (use: npm, pypi, go, docker, actions)", s)
			}
			ecos = append(ecos, e)
		}
		setup.ecoFlag = true
	}
	var err error
	failOn := f.failOn
	if failOn == "" {
		if f.ci {
			failOn = cfg.FailOn
		} else {
			failOn = "none"
		}
	}
	if setup.failOn, err = model.ParseSeverity(failOn); err != nil {
		return nil, usageErr("--fail-on: %v", err)
	}
	if setup.only, err = model.ParseSeverityList(f.only); err != nil {
		return nil, usageErr("--only: %v", err)
	}
	if setup.minSev, err = model.ParseSeverity(f.minSev); err != nil {
		return nil, usageErr("--min-severity: %v", err)
	}
	switch f.format {
	case "table", "json", "markdown", "md", "github":
	default:
		return nil, usageErr("unknown format %q (use: table, json, markdown, github)", f.format)
	}

	alPath := cfg.AllowlistFile
	if !filepath.IsAbs(alPath) {
		base := dir
		if st, err := os.Stat(dir); err == nil && !st.IsDir() {
			base = filepath.Dir(dir)
		}
		if cfgPath != "" {
			base = filepath.Dir(cfgPath)
		}
		alPath = filepath.Join(base, alPath)
	}
	al, err := allowlist.Load(alPath)
	if err != nil {
		return nil, usageErr("invalid allowlist: %v", err)
	}

	cch := cache.Default()
	store, err := db.Load(cch.Dir())
	if err != nil {
		return nil, err
	}
	offline := f.offline || os.Getenv("DEPSENTINEL_OFFLINE") != ""
	setup.progress = !f.quiet && !f.ci && term.IsTerminal(os.Stderr)
	setup.palette = term.Palette{Enabled: !f.ci && term.ColorEnabled(os.Stdout, f.noColor) && f.output == ""}
	setup.opts = engine.Options{
		Dir: dir, Ecosystems: ecos, NPMLock: f.lock, Offline: offline, NoRegistry: f.noRegistry, NoOSV: f.noOSV,
		Deep: f.deep, ProdOnly: f.prodOnly, Config: cfg, Allowlist: al, Store: store, Cache: cch,
		Endpoints: config.EndpointsFromEnv(),
	}
	if setup.progress {
		stderr := a.Stderr
		setup.opts.Log = func(format string, args ...any) { fmt.Fprintf(stderr, "→ "+format+"\n", args...) }
	}
	return setup, nil
}

func (a *App) cmdScan(ctx context.Context, args []string, audit bool) error {
	name, usage := "scan", "[ruta] [opciones]"
	if audit {
		name = "audit"
	}
	fs := newFlagSet(name, a.Stderr, usage)
	var f scanFlags
	f.register(fs, audit)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usageErr("too many arguments: %v", pos[1:])
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	}
	setup, err := a.prepare(&f, dir, false)
	if err != nil {
		return err
	}
	if audit && f.failOn == "" {
		setup.failOn = model.SeverityLow // audit falla si muestra algo
		if len(setup.only) > 0 {
			setup.failOn = setup.only[0]
			for _, s := range setup.only {
				if s < setup.failOn {
					setup.failOn = s
				}
			}
		}
	}
	start := time.Now()
	res, err := engine.Scan(ctx, setup.opts)
	if err != nil {
		return err
	}
	rep := res.Report
	if setup.ecoFlag && len(rep.Ecosystems) == 0 {
		return usageErr("no manifests found for %s in %s", f.ecosystem, dir)
	}
	if f.showAllow {
		rep.Findings = append(rep.Findings, rep.Suppressed...)
		model.SortFindings(rep.Findings)
	}

	var out io.Writer = a.Stdout
	if f.output != "" {
		file, err := os.Create(f.output)
		if err != nil {
			return fmt.Errorf("no puedo escribir %s: %w", f.output, err)
		}
		defer file.Close()
		out = file
	}
	switch f.format {
	case "json":
		if err := report.JSON(out, rep); err != nil {
			return err
		}
	case "markdown", "md":
		fmt.Fprint(out, report.Markdown(rep, report.MarkdownOptions{FailOn: setup.failOn, Only: setup.only, Min: setup.minSev, ReportURL: os.Getenv("DEPSENTINEL_REPORT_URL")}))
	case "github":
		report.GitHubAnnotations(out, rep)
	default:
		report.Table(out, rep, report.TableOptions{Color: setup.palette, MinSeverity: setup.minSev, Only: setup.only, FailOn: setup.failOn, CI: f.ci})
	}
	if f.outMD != "" {
		md := report.Markdown(rep, report.MarkdownOptions{FailOn: setup.failOn, Only: setup.only, Min: setup.minSev, ReportURL: os.Getenv("DEPSENTINEL_REPORT_URL")})
		if err := os.WriteFile(f.outMD, []byte(md), 0o644); err != nil {
			return fmt.Errorf("no puedo escribir %s: %w", f.outMD, err)
		}
	}
	if f.outHTML != "" {
		page, err := report.HTML(rep)
		if err != nil {
			return err
		}
		if err := os.WriteFile(f.outHTML, page, 0o644); err != nil {
			return fmt.Errorf("no puedo escribir %s: %w", f.outHTML, err)
		}
	}
	if f.ci && os.Getenv("GITHUB_ACTIONS") == "true" && f.format != "github" && f.output != "" {
		report.GitHubAnnotations(a.Stdout, rep)
	}
	if f.format != "json" || f.output != "" {
		report.Warnings(a.Stderr, rep, term.Palette{Enabled: term.ColorEnabled(os.Stderr, f.noColor) && !f.ci})
	}
	if setup.progress {
		fmt.Fprintf(a.Stderr, "Done in %s\n", engine.Elapsed(start))
	}
	if f.strict && rep.Incomplete {
		return &exitError{code: ExitIncomplete, msg: "incomplete analysis (--strict): a data source was unavailable"}
	}
	// --only también acota lo que cuenta para el umbral: lo que no se muestra no hace fallar
	if setup.failOn > model.SeverityNone && len(report.Filter(rep.Findings, setup.failOn, setup.only)) > 0 {
		return &exitError{code: ExitFindings}
	}
	return nil
}

// openBrowser abre una ruta o URL con el programa por defecto del sistema.
func openBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}
