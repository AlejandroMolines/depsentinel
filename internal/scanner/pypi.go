package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

type logicalLine struct {
	text string
	no   int
}

// readLogicalLines une las líneas que terminan en "\" (continuaciones).
func readLogicalLines(abs string) ([]logicalLine, error) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []logicalLine
	var cur strings.Builder
	start, n := 0, 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			if cur.Len() == 0 {
				start = n
			}
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteByte(' ')
			continue
		}
		if cur.Len() > 0 {
			cur.WriteString(line)
			out = append(out, logicalLine{cur.String(), start})
			cur.Reset()
			continue
		}
		out = append(out, logicalLine{line, n})
	}
	if cur.Len() > 0 {
		out = append(out, logicalLine{cur.String(), start})
	}
	return out, sc.Err()
}

var (
	reqName = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$`)
	pinRe   = regexp.MustCompile(`^===?\s*([0-9A-Za-z.!+_*-]+)$`)
	eggRe   = regexp.MustCompile(`#egg=([A-Za-z0-9._-]+)`)
)

func stripReqComment(s string) string {
	if strings.HasPrefix(strings.TrimSpace(s), "#") {
		return ""
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	return s
}

func hasOpt(s string, names ...string) bool {
	for _, n := range names {
		if s == n || strings.HasPrefix(s, n+" ") || strings.HasPrefix(s, n+"=") {
			return true
		}
	}
	return false
}

func optValue(s string) string {
	i := strings.IndexAny(s, " =")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(s[i+1:])
}

func isPublicPyPIIndex(u string) bool {
	return strings.Contains(u, "pypi.org") || strings.Contains(u, "files.pythonhosted.org")
}

// ParseRequirements lee requirements*.txt (incluye -r, extras, marcadores y --hash).
func ParseRequirements(abs, rel string) (*Result, error) {
	res := &Result{}
	if err := parseReqFile(abs, rel, map[string]bool{}, res, 0); err != nil {
		return nil, err
	}
	return res, nil
}

func parseReqFile(abs, rel string, visited map[string]bool, res *Result, depth int) error {
	real, _ := filepath.Abs(abs)
	if visited[real] {
		return nil
	}
	visited[real] = true
	lines, err := readLogicalLines(abs)
	if err != nil {
		return err
	}
	file := path.Base(rel)
	lowerFile := strings.ToLower(file)
	dev := strings.Contains(lowerFile, "dev") || strings.Contains(lowerFile, "test")
	start := len(res.Packages)
	privateIndex := false
	for _, ll := range lines {
		s := strings.TrimSpace(stripReqComment(ll.text))
		if s == "" {
			continue
		}
		switch {
		case hasOpt(s, "-r", "--requirement"):
			inc := optValue(s)
			if inc == "" || depth >= 5 {
				continue
			}
			if err := parseReqFile(filepath.Join(filepath.Dir(abs), inc), path.Join(path.Dir(rel), filepath.ToSlash(inc)), visited, res, depth+1); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s:%d: no se pudo leer %s: %v", rel, ll.no, inc, err))
			}
		case hasOpt(s, "-c", "--constraint"):
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s:%d: los ficheros de restricciones (-c) no se evalúan", rel, ll.no))
		case hasOpt(s, "-e", "--editable"):
			handleURLRequirement(optValue(s), rel, ll.no, res, dev)
		case hasOpt(s, "-i", "--index-url"):
			u := optValue(s)
			if !isPublicPyPIIndex(u) {
				privateIndex = true
			}
			if strings.HasPrefix(u, "http://") {
				res.Findings = append(res.Findings, staticFinding(model.PyPI, file, "", rel, ll.no, "index-url", "DS-INDEX-HTTP", model.SeverityHigh,
					"Índice de paquetes por HTTP sin cifrar", "pip descargaría paquetes sin cifrar desde "+shorten(u, 100)+".", "Usa un índice https://."))
			}
		case hasOpt(s, "--extra-index-url"):
			res.Findings = append(res.Findings, staticFinding(model.PyPI, file, "", rel, ll.no, "index-url", "DS-EXTRA-INDEX", model.SeverityMedium,
				"--extra-index-url abre la puerta a dependency confusion",
				"pip elige la versión más alta entre todos los índices: quien publique un paquete con el mismo nombre en PyPI puede ganar a tu índice privado.",
				"Usa un único índice (--index-url) o fija hashes con --require-hashes."))
		case hasOpt(s, "--trusted-host"):
			res.Findings = append(res.Findings, staticFinding(model.PyPI, file, "", rel, ll.no, "index-url", "DS-TRUSTED-HOST", model.SeverityMedium,
				"--trusted-host desactiva la verificación TLS", "pip aceptará cualquier certificado para "+shorten(optValue(s), 80)+".", "Instala la CA corporativa en lugar de desactivar la verificación."))
		case strings.HasPrefix(s, "-"):
			// otras opciones (--find-links, --pre, ...)
		default:
			addRequirement(s, rel, ll.no, res, dev)
		}
	}
	if privateIndex {
		for _, p := range res.Packages[start:] {
			p.Private = true
		}
	}
	return nil
}

func handleURLRequirement(s, rel string, no int, res *Result, dev bool) {
	name := ""
	if m := eggRe.FindStringSubmatch(s); m != nil {
		name = m[1]
	} else if i := strings.Index(s, " @ "); i > 0 {
		name = strings.TrimSpace(s[:i])
	}
	label := name
	if label == "" {
		label = shorten(s, 60)
	}
	res.Findings = append(res.Findings, staticFinding(model.PyPI, model.NormalizeName(model.PyPI, label), "", rel, no, "source", "DS-SOURCE-URL", model.SeverityMedium,
		"Dependencia instalada desde una URL o repositorio",
		"No pasa por PyPI: sin comprobación de publicador ni avisos de seguridad. Origen: "+shorten(s, 120),
		"Fija un commit exacto (@<sha>) y revisa el código, o publica el paquete en un índice."))
	if name != "" {
		res.Packages = append(res.Packages, &model.Package{
			Ecosystem: model.PyPI, Name: model.NormalizeName(model.PyPI, name), Source: rel, Line: no,
			Direct: true, Dev: dev, Private: true, Unpinned: true,
		})
	}
}

func addRequirement(s, rel string, no int, res *Result, dev bool) {
	if i := strings.Index(s, " --"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, ";"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if strings.Contains(s, "://") || strings.Contains(s, " @ ") {
		handleURLRequirement(s, rel, no, res, dev)
		return
	}
	m := reqName.FindStringSubmatch(s)
	if m == nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s:%d: línea no reconocida: %s", rel, no, shorten(s, 60)))
		return
	}
	pkg := &model.Package{
		Ecosystem: model.PyPI, Name: model.NormalizeName(model.PyPI, m[1]), Source: rel, Line: no,
		Direct: true, Dev: dev,
	}
	if pm := pinRe.FindStringSubmatch(strings.TrimSpace(m[2])); pm != nil && !strings.Contains(pm[1], "*") {
		pkg.Version = pm[1]
	} else {
		pkg.Unpinned = true
	}
	res.Packages = append(res.Packages, pkg)
}

type pipfileEntry struct {
	Version string `json:"version"`
	Git     string `json:"git"`
	Path    string `json:"path"`
	File    string `json:"file"`
}

// ParsePipfileLock lee Pipfile.lock (JSON).
func ParsePipfileLock(abs, rel string) (*Result, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Meta struct {
			Sources []struct {
				URL string `json:"url"`
			} `json:"sources"`
		} `json:"_meta"`
		Default map[string]pipfileEntry `json:"default"`
		Develop map[string]pipfileEntry `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("%s: JSON inválido: %w", rel, err)
	}
	privateIndex := false
	for _, s := range lock.Meta.Sources {
		if !isPublicPyPIIndex(s.URL) {
			privateIndex = true
		}
	}
	res := &Result{}
	add := func(m map[string]pipfileEntry, dev bool) {
		for name, e := range m {
			pkg := &model.Package{Ecosystem: model.PyPI, Name: model.NormalizeName(model.PyPI, name), Source: rel, Dev: dev, Direct: true, Private: privateIndex}
			if e.Git != "" || e.Path != "" || e.File != "" {
				pkg.Private = true
				pkg.Unpinned = true
				res.Findings = append(res.Findings, staticFinding(model.PyPI, pkg.Name, "", rel, 0, "source", "DS-SOURCE-URL", model.SeverityMedium,
					"Dependencia instalada desde git o una ruta local",
					"No pasa por PyPI: sin comprobación de publicador ni avisos de seguridad.",
					"Fija un commit exacto y revisa el código."))
			} else {
				pkg.Version = strings.TrimLeft(strings.TrimSpace(e.Version), "=")
				if pkg.Version == "" {
					pkg.Unpinned = true
				}
			}
			res.Packages = append(res.Packages, pkg)
		}
	}
	add(lock.Default, false)
	add(lock.Develop, true)
	sortPackages(res.Packages)
	return res, nil
}

func sortPackages(ps []*model.Package) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && ps[j].Name < ps[j-1].Name; j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return strings.Trim(v, `"'`)
}

type tomlPkg struct {
	name, version, category, groups string
	optional, skip, remote          bool
	line                            int
}

// ParsePythonTOMLLock lee poetry.lock y uv.lock (solo las claves [[package]] que necesita, sin dependencias externas).
func ParsePythonTOMLLock(abs, rel string) (*Result, error) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &Result{}
	var cur *tomlPkg
	sub := ""
	flush := func() {
		defer func() { cur = nil }()
		if cur == nil || cur.name == "" || cur.version == "" || cur.skip {
			return
		}
		pkg := &model.Package{
			Ecosystem: model.PyPI, Name: model.NormalizeName(model.PyPI, cur.name), Version: cur.version,
			Source: rel, Line: cur.line, Optional: cur.optional,
			Dev: cur.category == "dev" || (cur.groups != "" && !strings.Contains(cur.groups, "main")),
		}
		if cur.remote {
			pkg.Private = true
			res.Findings = append(res.Findings, staticFinding(model.PyPI, pkg.Name, pkg.Version, rel, cur.line, "source", "DS-SOURCE-URL", model.SeverityMedium,
				"Dependencia instalada desde git o una URL",
				"No pasa por PyPI: sin comprobación de publicador ni avisos de seguridad.",
				"Fija un commit exacto y revisa el código."))
		}
		res.Packages = append(res.Packages, pkg)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	no := 0
	for sc.Scan() {
		no++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[package]]" {
			flush()
			cur = &tomlPkg{line: no}
			sub = ""
			continue
		}
		if strings.HasPrefix(line, "[") {
			if cur != nil && (strings.HasPrefix(line, "[package.") || strings.HasPrefix(line, "[[package.")) {
				sub = line
			} else {
				flush()
				sub = ""
			}
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch {
		case sub == "":
			switch key {
			case "name":
				cur.name = unquote(val)
			case "version":
				cur.version = unquote(val)
			case "optional":
				cur.optional = val == "true"
			case "category":
				cur.category = unquote(val)
			case "groups":
				cur.groups = val
			case "source":
				if strings.Contains(val, "virtual") || strings.Contains(val, "editable") || strings.Contains(val, "directory") {
					cur.skip = true
				}
				if strings.Contains(val, "git =") || strings.Contains(val, "url =") {
					cur.remote = true
				}
			}
		case sub == "[package.source]" && key == "type":
			switch unquote(val) {
			case "git", "url":
				cur.remote = true
			case "directory", "file":
				cur.skip = true
			}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return res, nil
}
