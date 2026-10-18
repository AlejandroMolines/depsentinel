package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

type npmLock struct {
	Name            string               `json:"name"`
	Version         string               `json:"version"`
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]npmEntry  `json:"packages"`
	Dependencies    map[string]npmLegacy `json:"dependencies"`
}

type npmEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Link                 bool              `json:"link"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	DevOptional          bool              `json:"devOptional"`
	HasInstallScript     bool              `json:"hasInstallScript"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmLegacy struct {
	Version      string               `json:"version"`
	Resolved     string               `json:"resolved"`
	Integrity    string               `json:"integrity"`
	Dev          bool                 `json:"dev"`
	Optional     bool                 `json:"optional"`
	Requires     map[string]string    `json:"requires"`
	Dependencies map[string]npmLegacy `json:"dependencies"`
}

// ParseNPMLock lee package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2 y 3).
func ParseNPMLock(abs, rel string) (*Result, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("%s: JSON inválido: %w", rel, err)
	}
	direct, rootName, rootVersion := directFromPackageJSON(filepath.Dir(abs))
	res := &Result{RootName: firstNonEmpty(lock.Name, rootName), RootVersion: firstNonEmpty(lock.Version, rootVersion)}
	switch {
	case len(lock.Packages) > 0:
		parseNPMPackages(&lock, rel, direct, res)
	case len(lock.Dependencies) > 0:
		parseNPMLegacy(&lock, rel, direct, res)
	default:
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s no contiene dependencias", rel))
	}
	return res, nil
}

func directFromPackageJSON(dir string) (map[string]bool, string, string) {
	direct := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return direct, "", ""
	}
	var pj struct {
		Name                 string         `json:"name"`
		Version              string         `json:"version"`
		Dependencies         map[string]any `json:"dependencies"`
		DevDependencies      map[string]any `json:"devDependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
		PeerDependencies     map[string]any `json:"peerDependencies"`
	}
	_ = json.Unmarshal(b, &pj)
	for _, m := range []map[string]any{pj.Dependencies, pj.DevDependencies, pj.OptionalDependencies, pj.PeerDependencies} {
		for n := range m {
			direct[n] = true
		}
	}
	return direct, pj.Name, pj.Version
}

const nm = "node_modules/"

func nameFromPath(key string) string {
	i := strings.LastIndex(key, nm)
	if i < 0 {
		return ""
	}
	return key[i+len(nm):]
}

// topLevel indica si la ruta es node_modules/x (o <workspace>/node_modules/x), sin anidar.
func topLevel(key string) bool {
	i := strings.LastIndex(key, nm)
	return i >= 0 && !strings.Contains(key[:i], nm)
}

// resolveDep aplica el algoritmo de resolución de node: busca en node_modules desde el paquete hacia la raíz.
func resolveDep(exists func(string) bool, from, dep string) string {
	p := from
	for {
		cand := nm + dep
		if p != "" {
			cand = p + "/" + nm + dep
		}
		if exists(cand) {
			return cand
		}
		if p == "" {
			return ""
		}
		i := strings.LastIndex(p, nm)
		if i < 0 {
			p = ""
		} else {
			p = strings.TrimSuffix(p[:i], "/")
		}
	}
}

func isGitSource(r string) bool {
	for _, pre := range []string{"git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "ssh://"} {
		if strings.HasPrefix(r, pre) {
			return true
		}
	}
	if u, err := url.Parse(r); err == nil {
		switch u.Host {
		case "codeload.github.com", "github.com", "gitlab.com", "bitbucket.org":
			return true
		}
	}
	return false
}

// publicRegistryHost indica si el host es un registry público conocido de npm.
func publicRegistryHost(host string) bool {
	return host == "registry.npmjs.org" || host == "registry.yarnpkg.com"
}

// classifyResolved marca paquetes locales/git y devuelve hallazgos sobre el origen.
func classifyResolved(p *model.Package, rel string) []model.Finding {
	r := p.Resolved
	if r == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(r, "file:") || strings.HasPrefix(r, "link:") || strings.HasPrefix(r, "./") ||
		strings.HasPrefix(r, "../") || strings.HasPrefix(r, "/"):
		p.Private = true
		return nil
	case isGitSource(r):
		p.Private = true
		return []model.Finding{staticFinding(model.NPM, p.Name, p.Version, rel, 0, "source", "DS-SOURCE-GIT", model.SeverityMedium,
			"Dependencia instalada desde git o un tarball externo",
			"No pasa por el registry: no hay comprobación de publicador ni avisos de seguridad asociados. Origen: "+shorten(r, 120),
			"Prefiere una versión publicada en el registry o fija un commit exacto (#sha) y revisa el código.")}
	case strings.HasPrefix(r, "http://"):
		return []model.Finding{staticFinding(model.NPM, p.Name, p.Version, rel, 0, "source", "DS-SOURCE-HTTP", model.SeverityHigh,
			"Paquete descargado por HTTP sin cifrar",
			"Un atacante en la red podría sustituir el tarball. Origen: "+shorten(r, 120),
			"Cambia el registry a https:// y regenera el lockfile.")}
	}
	u, err := url.Parse(r)
	if err != nil {
		return nil
	}
	if publicRegistryHost(u.Host) && p.Integrity == "" {
		return []model.Finding{staticFinding(model.NPM, p.Name, p.Version, rel, 0, "integrity", "DS-INTEGRITY-MISSING", model.SeverityLow,
			"La entrada del lockfile no tiene hash de integridad",
			"Sin hash no se puede verificar que el tarball instalado es el publicado.",
			"Regenera el lockfile con una versión reciente de npm (npm install --package-lock-only).")}
	}
	return nil
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func parseNPMPackages(lock *npmLock, rel string, direct map[string]bool, res *Result) {
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" || !strings.Contains(k, nm) {
			e := lock.Packages[k]
			for _, m := range []map[string]string{e.Dependencies, e.DevDependencies, e.OptionalDependencies, e.PeerDependencies} {
				for n := range m {
					direct[n] = true
				}
			}
		}
	}
	byPath := map[string]*model.Package{}
	var order []string
	for _, k := range keys {
		if k == "" || !strings.Contains(k, nm) {
			continue
		}
		e := lock.Packages[k]
		if e.Link || e.Version == "" {
			continue
		}
		alias := nameFromPath(k)
		name := e.Name
		if name == "" {
			name = alias
		}
		p := &model.Package{
			Ecosystem: model.NPM, Name: name, Version: e.Version, Source: rel,
			Resolved: e.Resolved, Integrity: e.Integrity, HasInstallScript: e.HasInstallScript,
			Dev: e.Dev || e.DevOptional, Optional: e.Optional, Locations: []string{k},
			Direct: topLevel(k) && direct[alias],
		}
		res.Findings = append(res.Findings, classifyResolved(p, rel)...)
		byPath[k] = p
		order = append(order, k)
		res.Packages = append(res.Packages, p)
	}
	exists := func(s string) bool { _, ok := lock.Packages[s]; return ok }
	for _, k := range order {
		e := lock.Packages[k]
		p := byPath[k]
		seen := map[string]bool{}
		for _, m := range []map[string]string{e.Dependencies, e.OptionalDependencies, e.PeerDependencies} {
			for dep := range m {
				if q := byPath[resolveDep(exists, k, dep)]; q != nil && !seen[q.Key()] {
					seen[q.Key()] = true
					p.DependsOn = append(p.DependsOn, q.Key())
				}
			}
		}
		sort.Strings(p.DependsOn)
	}
}

type legacyNode struct {
	pkg      *model.Package
	requires map[string]string
}

func parseNPMLegacy(lock *npmLock, rel string, direct map[string]bool, res *Result) {
	nodes := map[string]*legacyNode{}
	var order []string
	var walk func(deps map[string]npmLegacy, prefix string, top bool)
	walk = func(deps map[string]npmLegacy, prefix string, top bool) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			d := deps[name]
			p := prefix + nm + name
			real, version, resolved := name, d.Version, d.Resolved
			if strings.HasPrefix(version, "npm:") {
				spec := strings.TrimPrefix(version, "npm:")
				if i := strings.LastIndex(spec, "@"); i > 0 {
					real, version = spec[:i], spec[i+1:]
				}
			}
			if resolved == "" && (strings.Contains(version, "/") || strings.Contains(version, ":")) {
				resolved = version
			}
			pkg := &model.Package{
				Ecosystem: model.NPM, Name: real, Version: version, Source: rel,
				Resolved: resolved, Integrity: d.Integrity, Dev: d.Dev, Optional: d.Optional,
				Locations: []string{p}, Direct: top && direct[name],
			}
			res.Findings = append(res.Findings, classifyResolved(pkg, rel)...)
			nodes[p] = &legacyNode{pkg: pkg, requires: d.Requires}
			order = append(order, p)
			res.Packages = append(res.Packages, pkg)
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies, p+"/", false)
			}
		}
	}
	walk(lock.Dependencies, "", true)
	exists := func(s string) bool { _, ok := nodes[s]; return ok }
	for _, k := range order {
		n := nodes[k]
		seen := map[string]bool{}
		for dep := range n.requires {
			if q := nodes[resolveDep(exists, k, dep)]; q != nil && !seen[q.pkg.Key()] {
				seen[q.pkg.Key()] = true
				n.pkg.DependsOn = append(n.pkg.DependsOn, q.pkg.Key())
			}
		}
		sort.Strings(n.pkg.DependsOn)
	}
}
