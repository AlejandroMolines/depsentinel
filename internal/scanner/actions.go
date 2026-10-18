package scanner

import (
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

var (
	usesRe      = regexp.MustCompile(`^(\s*)(?:-\s*)?uses:\s*['"]?([^\s'"#]+)['"]?\s*(?:#.*)?$`)
	fullSHARe   = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	exactVerRe  = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)
	runKeyRe    = regexp.MustCompile(`^(\s*)(?:-\s*)?(run|script):\s*(.*)$`)
	checkoutRef = regexp.MustCompile(`ref:\s*.*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)`)
	untrustedRe = regexp.MustCompile(`\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.(ref|label|repo\.full_name))|` +
		`comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.(message|author\.(email|name))|` +
		`commits\[[^\]]*\]\.(message|author\.(email|name)))|github\.head_ref)\s*\}\}`)
	branchLikeRe = regexp.MustCompile(`^(main|master|develop|dev|trunk|latest|head|stable|next|release/.+|v?\d+\.x)$`)
)

// ActionRef es una referencia "owner/repo[/ruta]@ref".
type ActionRef struct {
	Owner, Repo, Subpath, Ref string
}

// Name devuelve owner/repo.
func (a ActionRef) Name() string { return a.Owner + "/" + a.Repo }

// ParseActionRef descompone un valor de `uses:`; ok=false si es local (./) o docker://.
func ParseActionRef(uses string) (ActionRef, bool) {
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") || strings.HasPrefix(uses, "docker://") {
		return ActionRef{}, false
	}
	at := strings.LastIndex(uses, "@")
	if at <= 0 {
		return ActionRef{}, false
	}
	spec, ref := uses[:at], uses[at+1:]
	parts := strings.SplitN(spec, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ActionRef{}, false
	}
	a := ActionRef{Owner: parts[0], Repo: parts[1], Ref: ref}
	if len(parts) == 3 {
		a.Subpath = parts[2]
	}
	return a, true
}

func officialOwner(owner string) bool {
	o := strings.ToLower(owner)
	return o == "actions" || o == "github"
}

// ParseWorkflow analiza un workflow de GitHub Actions o una acción compuesta.
func ParseWorkflow(abs, rel string) (*Result, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	content := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(content, "\n")
	res := &Result{}
	file := path.Base(rel)
	seen := map[string]*model.Package{}

	hasPRTarget := strings.Contains(content, "pull_request_target")
	hasPerms := false
	for i, line := range lines {
		no := i + 1
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "permissions:") {
			hasPerms = true
			rest := strings.TrimSpace(strings.TrimPrefix(trim, "permissions:"))
			if rest == "write-all" {
				res.Findings = append(res.Findings, staticFinding(model.Actions, file, "", rel, no, "workflow-permissions", "DS-ACTIONS-WRITE-ALL", model.SeverityMedium,
					"El workflow pide permisos de escritura sobre todo (write-all)",
					"Si una acción de terceros se compromete, podrá modificar código, releases y secretos.",
					"Declara solo lo necesario, por ejemplo: permissions: { contents: read }."))
			}
		}
		if hasPRTarget && checkoutRef.MatchString(trim) {
			res.Findings = append(res.Findings, staticFinding(model.Actions, file, "", rel, no, "pwn-request", "DS-ACTIONS-PWN-REQUEST", model.SeverityHigh,
				"pull_request_target con checkout del código del PR",
				"El workflow se ejecuta con secretos y permisos de escritura sobre el código que envía un tercero (ataque «pwn request»).",
				"Usa pull_request, o separa el workflow en dos (uno sin privilegios que construye y otro que comenta) y no ejecutes código del PR."))
		}
		if m := usesRe.FindStringSubmatch(line); m != nil {
			addActionUse(m[2], rel, no, res, seen)
		}
	}
	if !hasPerms && strings.Contains(content, "jobs:") && !isActionDef(rel) {
		res.Findings = append(res.Findings, staticFinding(model.Actions, file, "", rel, 1, "workflow-permissions", "DS-ACTIONS-NO-PERMISSIONS", model.SeverityLow,
			"El workflow no declara permissions",
			"Sin permissions explícitos el GITHUB_TOKEN puede heredar permisos de escritura según la configuración del repositorio.",
			"Añade a nivel superior: permissions: { contents: read } y amplía solo donde haga falta."))
	}
	scanInjection(lines, rel, file, res)
	return res, nil
}

func addActionUse(uses, rel string, no int, res *Result, seen map[string]*model.Package) {
	if strings.HasPrefix(uses, "docker://") {
		ref := ParseImageRef(strings.TrimPrefix(uses, "docker://"))
		p := dockerPackage(ref, rel, no)
		res.Packages = append(res.Packages, p)
		res.Findings = append(res.Findings, imageFindings(p, ref, rel, no)...)
		return
	}
	a, ok := ParseActionRef(uses)
	if !ok {
		return
	}
	key := a.Name() + "@" + a.Ref
	p := seen[key]
	if p == nil {
		p = &model.Package{Ecosystem: model.Actions, Name: a.Name(), Version: a.Ref, Source: rel, Line: no, Direct: true}
		seen[key] = p
		res.Packages = append(res.Packages, p)
	}
	if fullSHARe.MatchString(a.Ref) {
		return
	}
	ref := strings.ToLower(a.Ref)
	switch {
	case branchLikeRe.MatchString(ref):
		res.Findings = append(res.Findings, staticFinding(model.Actions, a.Name(), a.Ref, rel, no, "action-pinning", "DS-ACTIONS-BRANCH", model.SeverityHigh,
			"Acción fijada a una rama mutable ("+a.Ref+")",
			"El código de "+a.Name()+" cambia con cada commit a esa rama: un compromiso del repositorio llega a tu CI sin que tú cambies nada.",
			"Fija la acción al SHA completo del commit: uses: "+a.Name()+"@<sha> # "+a.Ref))
	case officialOwner(a.Owner):
		res.Findings = append(res.Findings, staticFinding(model.Actions, a.Name(), a.Ref, rel, no, "action-pinning", "DS-ACTIONS-TAG", model.SeverityLow,
			"Official action pinned to a tag, not a SHA",
			"Los tags se pueden mover. El riesgo es menor en acciones de GitHub, pero sigue sin ser inmutable.",
			"Fija el SHA del commit: uses: "+a.Name()+"@<sha> # "+a.Ref))
	default:
		res.Findings = append(res.Findings, staticFinding(model.Actions, a.Name(), a.Ref, rel, no, "action-pinning", "DS-ACTIONS-TAG", model.SeverityMedium,
			"Acción de terceros fijada a un tag mutable ("+a.Ref+")",
			"Quien controle "+a.Owner+" puede mover el tag "+a.Ref+" a código malicioso (así ocurrió con tj-actions/changed-files en 2025).",
			"Fija el SHA del commit: uses: "+a.Name()+"@<sha> # "+a.Ref))
	}
}

// scanInjection busca expresiones ${{ ... }} controladas por terceros dentro de bloques run:/script:.
func scanInjection(lines []string, rel, file string, res *Result) {
	for i := 0; i < len(lines); i++ {
		m := runKeyRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		keyCol := strings.Index(lines[i], m[2])
		rest := strings.TrimSpace(m[3])
		report := func(no int, expr string) {
			res.Findings = append(res.Findings, staticFinding(model.Actions, file, "", rel, no, "workflow-injection", "DS-ACTIONS-INJECTION", model.SeverityHigh,
				"Inyección de comandos: dato externo usado directamente en un script",
				"La expresión "+expr+" se sustituye antes de ejecutar el shell: un título, rama o comentario manipulado puede ejecutar comandos en tu CI.",
				"Pásalo por una variable de entorno (env: TITLE: ${{ ... }}) y úsalo como \"$TITLE\" en el script."))
		}
		if rest != "" && rest != "|" && rest != ">" && !strings.HasPrefix(rest, "|") && !strings.HasPrefix(rest, ">") {
			if x := untrustedRe.FindString(rest); x != "" {
				report(i+1, x)
			}
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if strings.TrimSpace(l) == "" {
				continue
			}
			indent := len(l) - len(strings.TrimLeft(l, " \t"))
			if indent <= keyCol {
				break
			}
			if x := untrustedRe.FindString(l); x != "" {
				report(j+1, x)
			}
			i = j
		}
	}
}
