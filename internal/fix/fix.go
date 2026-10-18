// Package fix calcula y aplica arreglos automáticos (subir versiones directas, fijar acciones a un SHA).
package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/engine"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/registry"
	"github.com/AlejandroMolines/depsentinel/internal/semver"
)

// Action es un arreglo concreto.
type Action struct {
	Kind      string // bump-direct | bump-requirement | pin-action | manual
	Ecosystem model.Ecosystem
	Package   string
	From, To  string
	File      string // ruta relativa al directorio base
	Line      int
	Note      string
	Command   string
	Advisory  string
}

// Plan reúne lo que se puede aplicar solo y lo que requiere intervención humana.
type Plan struct {
	Edits    []Action
	Manual   []Action
	Warnings []string
}

// Options configura la planificación.
type Options struct {
	BaseDir string
	GitHub  *registry.GitHub // nil = sin conexión
}

func maxVersion(eco model.Ecosystem, vs []string) string {
	best := ""
	for _, v := range vs {
		if best == "" || semver.CompareEco(string(eco), v, best) > 0 {
			best = v
		}
	}
	return best
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BuildPlan analiza los hallazgos y propone arreglos.
func BuildPlan(ctx context.Context, o Options, res *engine.Result) (*Plan, error) {
	plan := &Plan{}
	rep, inv := res.Report, res.Inventory
	planNPM(o, plan, rep, inv)
	planPyPI(plan, rep)
	planPyPIUnpinned(plan, rep)
	planGo(plan, rep)
	planActions(ctx, o, plan, rep)
	planDocker(plan, rep)
	planMalicious(plan, rep)
	sort.SliceStable(plan.Edits, func(i, j int) bool {
		if plan.Edits[i].File != plan.Edits[j].File {
			return plan.Edits[i].File < plan.Edits[j].File
		}
		return plan.Edits[i].Line < plan.Edits[j].Line
	})
	return plan, nil
}

// ---------- npm ----------

var sectionNames = []string{"dependencies", "devDependencies", "optionalDependencies"}

func readDeclared(pkgJSON string) (map[string]string, map[string]string, error) {
	b, err := os.ReadFile(pkgJSON)
	if err != nil {
		return nil, nil, err
	}
	var pj map[string]json.RawMessage
	if err := json.Unmarshal(b, &pj); err != nil {
		return nil, nil, err
	}
	ranges, sections := map[string]string{}, map[string]string{}
	for _, sec := range sectionNames {
		raw, ok := pj[sec]
		if !ok {
			continue
		}
		var m map[string]string
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		for n, r := range m {
			if _, dup := ranges[n]; !dup {
				ranges[n], sections[n] = r, sec
			}
		}
	}
	return ranges, sections, nil
}

func newRange(old, fixed string) string {
	switch {
	case strings.HasPrefix(old, "~"):
		return "~" + fixed
	case strings.HasPrefix(old, "^"):
		return "^" + fixed
	case regexp.MustCompile(`^\d`).MatchString(old):
		return fixed
	}
	return "^" + fixed
}

func directAncestor(inv *engine.Inventory, key string) string {
	rev := map[string][]string{}
	byKey := map[string]*model.Package{}
	for _, p := range inv.Packages {
		byKey[p.Key()] = p
		for _, d := range p.DependsOn {
			rev[d] = append(rev[d], p.Key())
		}
	}
	seen := map[string]bool{key: true}
	queue := []string{key}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, parent := range rev[cur] {
			if seen[parent] {
				continue
			}
			seen[parent] = true
			if p := byKey[parent]; p != nil && p.Direct {
				return p.Name + "@" + p.Version
			}
			queue = append(queue, parent)
		}
	}
	return ""
}

func planNPM(o Options, plan *Plan, rep *model.Report, inv *engine.Inventory) {
	type group struct {
		fixes    []string
		versions map[string]bool
		ids      []string
	}
	groups := map[string]*group{}
	for _, f := range rep.Findings {
		if f.Ecosystem != model.NPM || f.Rule != "vulnerability" || f.FixedIn == "" {
			continue
		}
		g := groups[f.Package]
		if g == nil {
			g = &group{versions: map[string]bool{}}
			groups[f.Package] = g
		}
		g.fixes = append(g.fixes, f.FixedIn)
		g.versions[f.Version] = true
		g.ids = append(g.ids, f.ID)
	}
	for _, name := range sortedKeys(groups) {
		g := groups[name]
		fixed := maxVersion(model.NPM, g.fixes)
		var direct *model.Package
		var any *model.Package
		for _, p := range inv.Packages {
			if p.Ecosystem == model.NPM && p.Name == name && g.versions[p.Version] {
				any = p
				if p.Direct {
					direct = p
				}
			}
		}
		adv := strings.Join(g.ids, ", ")
		if direct == nil {
			ancestor := ""
			if any != nil {
				ancestor = directAncestor(inv, any.Key())
			}
			note := "Dependencia transitiva"
			if ancestor != "" {
				note += " (la trae " + ancestor + ")"
			}
			note += fmt.Sprintf(": prueba npm update %s; si no sube, actualiza el paquete que la trae o fuerza la versión con overrides en package.json: { \"overrides\": { \"%s\": \"^%s\" } }.", name, name, fixed)
			plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.NPM, Package: name, To: fixed, Note: note, Command: "npm update " + name, Advisory: adv})
			continue
		}
		pkgJSONRel := path.Join(path.Dir(direct.Source), "package.json")
		ranges, _, err := readDeclared(filepath.Join(o.BaseDir, filepath.FromSlash(pkgJSONRel)))
		declared, ok := ranges[name]
		if err != nil || !ok {
			plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.NPM, Package: name, To: fixed,
				Note: "No encuentro la dependencia en " + pkgJSONRel + ": actualízala a mano.", Command: fmt.Sprintf("npm install %s@%s", name, fixed), Advisory: adv})
			continue
		}
		if semver.CompareStrings(semver.LowerBound(declared), fixed) >= 0 {
			plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.NPM, Package: name, From: declared, To: fixed,
				Note: "El package.json ya permite " + fixed + ": solo hay que refrescar el lockfile.", Command: "npm update " + name, Advisory: adv})
			continue
		}
		plan.Edits = append(plan.Edits, Action{Kind: "bump-direct", Ecosystem: model.NPM, Package: name, From: declared,
			To: newRange(declared, fixed), File: pkgJSONRel, Advisory: adv,
			Note: "Después ejecuta npm install para regenerar el lockfile."})
	}
}

// ---------- PyPI ----------

func planPyPI(plan *Plan, rep *model.Report) {
	type key struct {
		file string
		line int
		name string
	}
	type val struct {
		fixes []string
		from  string
		ids   []string
	}
	edits := map[key]*val{}
	for _, f := range rep.Findings {
		if f.Ecosystem != model.PyPI || f.Rule != "vulnerability" || f.FixedIn == "" {
			continue
		}
		base := strings.ToLower(path.Base(f.Source))
		switch {
		case strings.HasSuffix(base, ".txt") && f.Line > 0:
			k := key{f.Source, f.Line, f.Package}
			v := edits[k]
			if v == nil {
				v = &val{from: f.Version}
				edits[k] = v
			}
			v.fixes = append(v.fixes, f.FixedIn)
			v.ids = append(v.ids, f.ID)
		default:
			cmd := fmt.Sprintf("pip install --upgrade '%s>=%s'", f.Package, f.FixedIn)
			switch base {
			case "poetry.lock":
				cmd = "poetry update " + f.Package
			case "pipfile.lock":
				cmd = "pipenv update " + f.Package
			case "uv.lock":
				cmd = "uv lock --upgrade-package " + f.Package
			}
			plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.PyPI, Package: f.Package, From: f.Version, To: f.FixedIn,
				File: f.Source, Command: cmd, Advisory: f.ID, Note: "Actualiza a " + f.FixedIn + " o superior y regenera el lock."})
		}
	}
	keys := make([]key, 0, len(edits))
	for k := range edits {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].file != keys[j].file {
			return keys[i].file < keys[j].file
		}
		return keys[i].line < keys[j].line
	})
	for _, k := range keys {
		v := edits[k]
		plan.Edits = append(plan.Edits, Action{Kind: "bump-requirement", Ecosystem: model.PyPI, Package: k.name, From: v.from,
			To: maxVersion(model.PyPI, v.fixes), File: k.file, Line: k.line, Advisory: strings.Join(v.ids, ", ")})
	}
}

// planPyPIUnpinned propone generar un lockfile para las dependencias PyPI sin versión exacta.
func planPyPIUnpinned(plan *Plan, rep *model.Report) {
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Ecosystem != model.PyPI || f.Rule != "unpinned" {
			continue
		}
		base := strings.ToLower(path.Base(f.Source))
		if seen[base] {
			continue
		}
		seen[base] = true
		cmd := "pip-compile --generate-hashes requirements.in"
		note := "Generate a lockfile with exact versions and hashes, then scan it."
		switch base {
		case "pyproject.toml":
			cmd = "poetry lock"
			note = "Generate poetry.lock and scan it."
		case "uv.lock":
			cmd = "uv lock"
			note = "Generate uv.lock and scan it."
		case "pipfile":
			cmd = "pipenv lock"
			note = "Generate Pipfile.lock and scan it."
		}
		plan.Manual = append(plan.Manual, Action{
			Kind: "manual", Ecosystem: model.PyPI, Package: f.Package, File: f.Source,
			Command: cmd, Advisory: f.ID, Note: note,
		})
	}
}

// ---------- Go ----------

func planGo(plan *Plan, rep *model.Report) {
	type g struct {
		fixes []string
		ids   []string
		from  string
	}
	groups := map[string]*g{}
	for _, f := range rep.Findings {
		if f.Ecosystem != model.Go || f.Rule != "vulnerability" || f.FixedIn == "" {
			continue
		}
		x := groups[f.Package]
		if x == nil {
			x = &g{from: f.Version}
			groups[f.Package] = x
		}
		x.fixes = append(x.fixes, f.FixedIn)
		x.ids = append(x.ids, f.ID)
	}
	for _, name := range sortedKeys(groups) {
		x := groups[name]
		to := maxVersion(model.Go, x.fixes)
		plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.Go, Package: name, From: x.from, To: to,
			Command: fmt.Sprintf("go get %s@%s && go mod tidy", name, to), Advisory: strings.Join(x.ids, ", ")})
	}
}

// ---------- GitHub Actions ----------

func planActions(ctx context.Context, o Options, plan *Plan, rep *model.Report) {
	cache := map[string]string{}
	failed := map[string]bool{}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Ecosystem != model.Actions || f.Rule != "action-pinning" || f.Line == 0 {
			continue
		}
		k := fmt.Sprintf("%s:%d", f.Source, f.Line)
		if seen[k] {
			continue
		}
		seen[k] = true
		ref := f.Version
		parts := strings.SplitN(f.Package, "/", 2)
		if len(parts) != 2 {
			continue
		}
		ck := f.Package + "@" + ref
		if o.GitHub == nil {
			plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.Actions, Package: f.Package, From: ref, File: f.Source, Line: f.Line,
				Note: "Sin conexión: no puedo resolver el SHA. Fija la acción al SHA del commit de " + ref + "."})
			continue
		}
		sha, ok := cache[ck]
		if !ok && !failed[ck] {
			s, err := o.GitHub.ResolveRef(ctx, parts[0], parts[1], ref)
			if err != nil {
				failed[ck] = true
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("No se pudo resolver %s@%s: %v", f.Package, ref, err))
			} else {
				cache[ck], sha, ok = s, s, true
			}
		}
		if !ok {
			plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.Actions, Package: f.Package, From: ref, File: f.Source, Line: f.Line,
				Note: "Fija la acción al SHA completo del commit de " + ref + "."})
			continue
		}
		plan.Edits = append(plan.Edits, Action{Kind: "pin-action", Ecosystem: model.Actions, Package: f.Package, From: ref, To: sha, File: f.Source, Line: f.Line,
			Note: "Quedará como uses: " + f.Package + "@" + sha[:12] + "… # " + ref})
	}
}

// ---------- Docker y malware ----------

func planDocker(plan *Plan, rep *model.Report) {
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Ecosystem != model.Docker || (f.Rule != "image-tag" && f.Rule != "image-digest") {
			continue
		}
		k := f.Package + ":" + f.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		tag := f.Version
		if tag == "latest" {
			tag = "<versión>"
		}
		plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: model.Docker, Package: f.Package, From: f.Version, File: f.Source, Line: f.Line,
			Command: fmt.Sprintf("docker buildx imagetools inspect %s:%s", f.Package, tag),
			Note:    "Fija la versión y el digest en el FROM (el comando muestra el digest)."})
	}
}

func planMalicious(plan *Plan, rep *model.Report) {
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Rule != "malicious" || seen[f.PackageKey()] {
			continue
		}
		seen[f.PackageKey()] = true
		cmd := ""
		switch f.Ecosystem {
		case model.NPM:
			cmd = "npm uninstall " + f.Package
		case model.PyPI:
			cmd = "pip uninstall " + f.Package
		}
		plan.Manual = append(plan.Manual, Action{Kind: "manual", Ecosystem: f.Ecosystem, Package: f.Package, From: f.Version, File: f.Source, Command: cmd, Advisory: f.ID,
			Note: "PAQUETE MALICIOSO O COMPROMETIDO: elimínalo y rota las credenciales accesibles durante la instalación."})
	}
}

// ---------- vista previa y aplicación ----------

func describe(a Action) string {
	switch a.Kind {
	case "bump-direct":
		return fmt.Sprintf("%s: \"%s\" → \"%s\"", a.Package, a.From, a.To)
	case "bump-requirement":
		return fmt.Sprintf("%s: ==%s → ==%s", a.Package, a.From, a.To)
	case "pin-action":
		return fmt.Sprintf("%s: @%s → @%s # %s", a.Package, a.From, shortSHA(a.To), a.From)
	}
	return a.Package
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// Preview escribe el plan en forma legible.
func (p *Plan) Preview(w io.Writer, dryRun bool) {
	if len(p.Edits) == 0 && len(p.Manual) == 0 {
		fmt.Fprintln(w, "No hay nada que arreglar automáticamente.")
	}
	if len(p.Edits) > 0 {
		if dryRun {
			fmt.Fprintln(w, "Cambios que se aplicarían (--dry-run: no se ha modificado nada):")
		} else {
			fmt.Fprintln(w, "Cambios aplicados:")
		}
		cur := ""
		for _, a := range p.Edits {
			if a.File != cur {
				cur = a.File
				fmt.Fprintf(w, "\n  %s\n", cur)
			}
			line := ""
			if a.Line > 0 {
				line = fmt.Sprintf(" (línea %d)", a.Line)
			}
			fmt.Fprintf(w, "    %s%s\n", describe(a), line)
			if a.Advisory != "" {
				fmt.Fprintf(w, "      avisos: %s\n", a.Advisory)
			}
		}
		fmt.Fprintln(w)
	}
	if len(p.Manual) > 0 {
		fmt.Fprintln(w, "Requiere intervención manual:")
		for _, a := range p.Manual {
			fmt.Fprintf(w, "  • %s %s", a.Ecosystem.Label(), a.Package)
			if a.To != "" {
				fmt.Fprintf(w, " → %s", a.To)
			}
			fmt.Fprintln(w)
			if a.Note != "" {
				fmt.Fprintf(w, "      %s\n", a.Note)
			}
			if a.Command != "" {
				fmt.Fprintf(w, "      $ %s\n", a.Command)
			}
		}
	}
	for _, x := range p.Warnings {
		fmt.Fprintf(w, "warning: %s\n", x)
	}
}

// Apply escribe los cambios en disco y devuelve los ficheros modificados.
func (p *Plan) Apply(baseDir string) ([]string, error) {
	byFile := map[string][]Action{}
	for _, a := range p.Edits {
		byFile[a.File] = append(byFile[a.File], a)
	}
	var changed []string
	for _, file := range sortedKeys(byFile) {
		abs := filepath.Join(baseDir, filepath.FromSlash(file))
		st, err := os.Stat(abs)
		if err != nil {
			return changed, err
		}
		src, err := os.ReadFile(abs)
		if err != nil {
			return changed, err
		}
		var out []byte
		switch byFile[file][0].Kind {
		case "bump-direct":
			out, err = bumpPackageJSON(src, byFile[file])
		default:
			out, err = editLines(src, byFile[file])
		}
		if err != nil {
			return changed, fmt.Errorf("%s: %w", file, err)
		}
		if bytes.Equal(src, out) {
			continue
		}
		tmp := abs + ".depsentinel.tmp"
		if err := os.WriteFile(tmp, out, st.Mode().Perm()); err != nil {
			return changed, err
		}
		if err := os.Rename(tmp, abs); err != nil {
			return changed, err
		}
		changed = append(changed, file)
	}
	return changed, nil
}

// sectionRanges devuelve el rango de bytes (": { ... }") de cada clave de primer nivel.
func sectionRanges(src []byte) (map[string][2]int, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("se esperaba un objeto JSON")
	}
	out := map[string][2]int{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		start := int(dec.InputOffset())
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		out[key] = [2]int{start, int(dec.InputOffset())}
	}
	return out, nil
}

// bumpPackageJSON cambia rangos de dependencias sin reordenar ni reformatear el resto del fichero.
func bumpPackageJSON(src []byte, actions []Action) ([]byte, error) {
	cur := append([]byte(nil), src...)
	for _, a := range actions {
		ranges, err := sectionRanges(cur)
		if err != nil {
			return nil, err
		}
		done := false
		for _, sec := range sectionNames {
			r, ok := ranges[sec]
			if !ok {
				continue
			}
			re := regexp.MustCompile(`("` + regexp.QuoteMeta(a.Package) + `"\s*:\s*")` + regexp.QuoteMeta(a.From) + `(")`)
			section := cur[r[0]:r[1]]
			if !re.Match(section) {
				continue
			}
			replaced := re.ReplaceAll(section, []byte("${1}"+a.To+"${2}"))
			next := append(append(append([]byte(nil), cur[:r[0]]...), replaced...), cur[r[1]:]...)
			cur = next
			done = true
			break
		}
		if !done {
			return nil, fmt.Errorf("no encuentro %s: \"%s\" en package.json", a.Package, a.From)
		}
	}
	if !json.Valid(cur) {
		return nil, fmt.Errorf("el resultado no es un JSON válido (no se escribe nada)")
	}
	return cur, nil
}

// editLines aplica cambios por línea (requirements*.txt y workflows).
func editLines(src []byte, actions []Action) ([]byte, error) {
	lines := strings.Split(string(src), "\n")
	for _, a := range actions {
		i := a.Line - 1
		if i < 0 || i >= len(lines) {
			return nil, fmt.Errorf("la línea %d ya no existe", a.Line)
		}
		line := lines[i]
		cr := ""
		if strings.HasSuffix(line, "\r") {
			cr, line = "\r", strings.TrimSuffix(line, "\r")
		}
		switch a.Kind {
		case "bump-requirement":
			if strings.Contains(line, "--hash") {
				return nil, fmt.Errorf("la línea %d lleva hashes (--hash): actualiza con pip-compile para regenerarlos", a.Line)
			}
			re := regexp.MustCompile(`(===?)\s*` + regexp.QuoteMeta(a.From) + `\b`)
			if !re.MatchString(line) {
				return nil, fmt.Errorf("la línea %d no contiene ==%s", a.Line, a.From)
			}
			line = re.ReplaceAllString(line, "${1}"+a.To)
		case "pin-action":
			re := regexp.MustCompile(`(` + regexp.QuoteMeta(a.Package) + `(?:/[^@\s'"]*)?)@` + regexp.QuoteMeta(a.From) + `(['"]?)`)
			if !strings.Contains(line, "uses:") || !re.MatchString(line) {
				return nil, fmt.Errorf("la línea %d ya no contiene %s@%s", a.Line, a.Package, a.From)
			}
			line = re.ReplaceAllString(line, "${1}@"+a.To+"${2} # "+a.From)
		}
		lines[i] = line + cr
	}
	return []byte(strings.Join(lines, "\n")), nil
}
