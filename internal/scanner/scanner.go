// Package scanner detecta manifiestos y los convierte en paquetes y hallazgos estáticos.
package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// Result es lo que produce el análisis de un manifiesto.
type Result struct {
	Packages    []*model.Package
	Findings    []model.Finding
	Warnings    []string
	RootName    string
	RootVersion string
}

// Files agrupa rutas relativas (con "/") por ecosistema.
type Files map[model.Ecosystem][]string

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "__pycache__": true,
	".next": true, "target": true, "testdata": true, ".depsentinel": true, ".tox": true, ".mypy_cache": true,
	".idea": true, ".gradle": true,
}

const (
	maxDepth   = 8
	maxEntries = 200000
)

func ignored(rel string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
		if ok, _ := path.Match(p, rel); ok {
			return true
		}
		if ok, _ := path.Match(p, path.Base(rel)); ok {
			return true
		}
	}
	return false
}

// Classify indica a qué ecosistema pertenece un fichero (por su ruta relativa).
func Classify(rel string) (model.Ecosystem, bool) {
	base := path.Base(rel)
	lower := strings.ToLower(base)
	dir := path.Dir(rel)
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		return model.NPM, true
	case lower == "pipfile.lock" || lower == "poetry.lock" || lower == "uv.lock":
		return model.PyPI, true
	case strings.HasSuffix(lower, ".txt") && (strings.HasPrefix(lower, "requirements") ||
		strings.HasSuffix(lower, "requirements.txt") || path.Base(dir) == "requirements"):
		return model.PyPI, true
	case base == "go.mod":
		return model.Go, true
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile") ||
		lower == "containerfile" || strings.HasPrefix(lower, "containerfile."):
		return model.Docker, true
	case isCompose(lower):
		return model.Docker, true
	case isWorkflow(rel), isActionDef(rel):
		return model.Actions, true
	}
	return "", false
}

func isCompose(lower string) bool {
	if !(strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")) {
		return false
	}
	return strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose")
}

func isWorkflow(rel string) bool {
	if !(strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml")) {
		return false
	}
	i := strings.Index("/"+rel, "/.github/workflows/")
	if i < 0 {
		return false
	}
	rest := ("/" + rel)[i+len("/.github/workflows/"):]
	return !strings.Contains(rest, "/")
}

func isActionDef(rel string) bool {
	base := path.Base(rel)
	if base != "action.yml" && base != "action.yaml" {
		return false
	}
	return rel == base || strings.Contains("/"+rel, "/.github/actions/")
}

// Detect recorre root y devuelve los manifiestos soportados.
func Detect(root string, ignore []string) (Files, error) {
	files := Files{}
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		if eco, ok := Classify(filepath.ToSlash(filepath.Base(root))); ok {
			files[eco] = append(files[eco], filepath.ToSlash(filepath.Base(root)))
		}
		return files, nil
	}
	count := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if skipDirs[d.Name()] || ignored(rel, ignore) || strings.Count(rel, "/") >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if ignored(rel, ignore) {
			return nil
		}
		count++
		if count > maxEntries {
			return filepath.SkipAll
		}
		if eco, ok := Classify(rel); ok {
			files[eco] = append(files[eco], rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for k := range files {
		sort.Strings(files[k])
	}
	return files, nil
}

// Parse analiza un manifiesto según su ecosistema.
func Parse(eco model.Ecosystem, abs, rel string) (*Result, error) {
	base := strings.ToLower(path.Base(rel))
	switch eco {
	case model.NPM:
		return ParseNPMLock(abs, rel)
	case model.PyPI:
		switch base {
		case "pipfile.lock":
			return ParsePipfileLock(abs, rel)
		case "poetry.lock", "uv.lock":
			return ParsePythonTOMLLock(abs, rel)
		}
		return ParseRequirements(abs, rel)
	case model.Go:
		return ParseGoMod(abs, rel)
	case model.Docker:
		if isCompose(base) {
			return ParseCompose(abs, rel)
		}
		return ParseDockerfile(abs, rel)
	case model.Actions:
		return ParseWorkflow(abs, rel)
	}
	return nil, fmt.Errorf("ecosistema no soportado: %s", eco)
}

// staticFinding construye un hallazgo estático asociado a un paquete (o a un nombre de fichero).
func staticFinding(eco model.Ecosystem, name, version, rel string, line int, rule, id string, sev model.Severity, title, detail, fix string) model.Finding {
	return model.Finding{
		ID: id, Rule: rule, Severity: sev, Ecosystem: eco, Package: name, Version: version,
		Title: title, Detail: detail, Fix: fix, Source: rel, Line: line,
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
