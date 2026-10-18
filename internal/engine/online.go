package engine

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/osv"
	"github.com/AlejandroMolines/depsentinel/internal/registry"
	"github.com/AlejandroMolines/depsentinel/internal/rules"
	"github.com/AlejandroMolines/depsentinel/internal/semver"
	"github.com/AlejandroMolines/depsentinel/internal/workpool"
)

var exactVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// osvQuery traduce un paquete al vocabulario de OSV (false si no se puede consultar).
func osvQuery(p *model.Package) (osv.Query, bool) {
	eco := p.Ecosystem.OSV()
	if eco == "" || p.Private || p.Name == "" || p.Version == "" || strings.Contains(p.Name, "$") {
		return osv.Query{}, false
	}
	v := p.Version
	switch p.Ecosystem {
	case model.Go:
		v = strings.TrimSuffix(strings.TrimPrefix(v, "v"), "+incompatible")
	case model.Actions:
		if !exactVersion.MatchString(v) {
			return osv.Query{}, false
		}
		v = strings.TrimPrefix(v, "v")
	case model.NPM:
		if _, ok := semver.Parse(v); !ok {
			return osv.Query{}, false
		}
	}
	return osv.Query{Ecosystem: eco, Name: p.Name, Version: v}, true
}

// queryOSV consulta OSV por todos los paquetes y devuelve los avisos por clave de paquete.
func queryOSV(ctx context.Context, o *Options, pkgs []*model.Package) (map[string][]*osv.Vuln, []string, bool) {
	var items []*model.Package
	var queries []osv.Query
	for _, p := range pkgs {
		if q, ok := osvQuery(p); ok {
			items = append(items, p)
			queries = append(queries, q)
		}
	}
	out := map[string][]*osv.Vuln{}
	if len(queries) == 0 {
		return out, nil, false
	}
	o.Log("Querying OSV (%d packages)…", len(queries))
	client := osv.New(o.HTTP, o.Endpoints.OSV, o.Cache)
	client.Workers = o.Config.Network.Concurrency
	refs, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return out, []string{"No se pudo consultar OSV, así que CVEs y malware conocido NO se han evaluado: " + err.Error()}, true
	}
	var all []osv.VulnRef
	for _, r := range refs {
		all = append(all, r...)
	}
	vulns, failed, ferr := client.FetchVulns(ctx, all)
	for i, p := range items {
		for _, r := range refs[i] {
			if v := vulns[r.ID]; v != nil && v.Withdrawn == "" {
				out[p.Key()] = append(out[p.Key()], v)
			}
		}
	}
	var warns []string
	if failed > 0 {
		warns = append(warns, fmt.Sprintf("OSV: no se pudo descargar el detalle de %d aviso(s) (%v); esos avisos no aparecen en el informe.", failed, ferr))
	}
	return out, warns, failed > 0
}

func npmPublic(p *model.Package) bool {
	if p.Private {
		return false
	}
	if p.Resolved == "" {
		return true
	}
	u, err := url.Parse(p.Resolved)
	if err != nil {
		return false
	}
	return u.Host == "registry.npmjs.org" || u.Host == "registry.yarnpkg.com"
}

type errCollector struct {
	mu    sync.Mutex
	n     int
	first error
}

func (e *errCollector) add(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.n++
	if e.first == nil {
		e.first = err
	}
}

func (e *errCollector) warn(what string) []string {
	if e.n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("No se pudieron consultar %d paquete(s) de %s (primer error: %v); sus metadatos no se han evaluado.", e.n, what, e.first)}
}

// enrich completa Package.Meta consultando los registries públicos.
func enrich(ctx context.Context, o *Options, pkgs []*model.Package) ([]string, bool) {
	var warns []string
	incomplete := false
	workers := o.Config.Network.Concurrency

	// npm
	var npmPkgs []*model.Package
	for _, p := range pkgs {
		if p.Ecosystem == model.NPM && npmPublic(p) && p.Version != "" {
			npmPkgs = append(npmPkgs, p)
		}
	}
	if len(npmPkgs) > 0 {
		o.Log("Querying the npm registry (%d packages)…", len(npmPkgs))
		client := registry.NewNPM(o.HTTP, o.Endpoints.NPM, o.Cache)
		type group struct {
			name     string
			versions []string
			deep     bool
		}
		groups := map[string]*group{}
		for _, p := range npmPkgs {
			g := groups[p.Name]
			if g == nil {
				g = &group{name: p.Name}
				groups[p.Name] = g
			}
			g.versions = append(g.versions, p.Version)
			if p.Direct || p.HasInstallScript {
				g.deep = true
			}
		}
		names := make([]string, 0, len(groups))
		for n := range groups {
			names = append(names, n)
		}
		sort.Strings(names)
		metas := make([]map[string]*model.Meta, len(names))
		var ec errCollector
		run := func(idx []int, forceDeep bool) {
			workpool.ForEach(ctx, workers, len(idx), func(ctx context.Context, i int) {
				k := idx[i]
				g := groups[names[k]]
				m, err := client.Metas(ctx, g.name, g.versions, g.deep || forceDeep)
				if err != nil {
					ec.add(fmt.Errorf("%s: %w", g.name, err))
				}
				if len(m) > 0 {
					metas[k] = m
				}
			})
		}
		all := make([]int, len(names))
		for i := range all {
			all[i] = i
		}
		run(all, false)
		// los paquetes con scripts de instalación descubiertos con la vista abreviada se completan
		var again []int
		for k, m := range metas {
			for _, meta := range m {
				if meta.HasInstallScript && !meta.Deep {
					again = append(again, k)
					break
				}
			}
		}
		if len(again) > 0 {
			run(again, true)
		}
		byName := map[string]map[string]*model.Meta{}
		for k, n := range names {
			byName[n] = metas[k]
		}
		for _, p := range npmPkgs {
			if m := byName[p.Name][p.Version]; m != nil {
				p.Meta = m
				if m.HasInstallScript {
					p.HasInstallScript = true
				}
			}
		}
		if w := ec.warn("npm"); w != nil {
			warns = append(warns, w...)
			incomplete = true
		}
	}

	// PyPI
	var pyPkgs []*model.Package
	for _, p := range pkgs {
		if p.Ecosystem == model.PyPI && !p.Private && p.Version != "" {
			pyPkgs = append(pyPkgs, p)
		}
	}
	if len(pyPkgs) > 0 {
		o.Log("Querying PyPI (%d packages)…", len(pyPkgs))
		client := registry.NewPyPI(o.HTTP, o.Endpoints.PyPI, o.Cache)
		var ec errCollector
		workpool.ForEach(ctx, workers, len(pyPkgs), func(ctx context.Context, i int) {
			m, err := client.Meta(ctx, pyPkgs[i].Name, pyPkgs[i].Version)
			if err != nil {
				ec.add(fmt.Errorf("%s: %w", pyPkgs[i].Name, err))
				return
			}
			pyPkgs[i].Meta = m
		})
		if w := ec.warn("PyPI"); w != nil {
			warns = append(warns, w...)
			incomplete = true
		}
	}

	// Go
	var goPkgs []*model.Package
	for _, p := range pkgs {
		if p.Ecosystem == model.Go && !p.Private && p.Version != "" {
			goPkgs = append(goPkgs, p)
		}
	}
	if len(goPkgs) > 0 {
		o.Log("Querying the Go module proxy (%d modules)…", len(goPkgs))
		client := registry.NewGoProxy(o.HTTP, o.Endpoints.GoProxy, o.Cache)
		var ec errCollector
		workpool.ForEach(ctx, workers, len(goPkgs), func(ctx context.Context, i int) {
			m, err := client.Meta(ctx, goPkgs[i].Name, goPkgs[i].Version)
			if err != nil {
				ec.add(fmt.Errorf("%s: %w", goPkgs[i].Name, err))
				return
			}
			// un módulo ausente del proxy suele ser privado (GOPRIVATE): no es una señal fiable
			if m.PackageMissing || m.VersionMissing {
				return
			}
			goPkgs[i].Meta = m
		})
		if w := ec.warn("Go"); w != nil {
			warns = append(warns, w...)
			incomplete = true
		}
	}
	return warns, incomplete
}

// deepScan descarga los tarballs de los paquetes con scripts de instalación, verifica su hash
// e inspecciona los ficheros que esos scripts ejecutan.
func deepScan(ctx context.Context, o *Options, pkgs []*model.Package) ([]model.Finding, []string, bool) {
	var targets []*model.Package
	for _, p := range pkgs {
		if p.Ecosystem == model.NPM && p.Meta != nil && p.Meta.Deep && p.Meta.Tarball != "" && len(p.Meta.InstallScripts) > 0 && !p.Private {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		return nil, nil, false
	}
	o.Log("Inspeccionando %d paquete(s) con scripts de instalación (--deep)…", len(targets))
	client := registry.NewNPM(o.HTTP, o.Endpoints.NPM, o.Cache)
	var mu sync.Mutex
	var findings []model.Finding
	var ec errCollector
	workpool.ForEach(ctx, 4, len(targets), func(ctx context.Context, i int) {
		p := targets[i]
		data, err := client.FetchTarball(ctx, p.Meta.Tarball, strings.TrimSpace(p.Integrity+" "+p.Meta.RegistryIntegrity))
		var ie *registry.ErrIntegrity
		if err != nil {
			if asIntegrity(err, &ie) {
				f := model.Finding{
					ID: "DS-INTEGRITY-MISMATCH", Rule: "integrity", Severity: model.SeverityCritical, Ecosystem: p.Ecosystem,
					Package: p.Name, Version: p.Version, Source: p.Source,
					Title:  "El tarball descargado no coincide con el hash del lockfile",
					Detail: "El registry sirve un contenido distinto al que quedó registrado en el lockfile. Las versiones publicadas son inmutables: esto indica manipulación del paquete, del registry o del lockfile.",
					Fix:    "No instales este paquete. Compara el lockfile con el de tu repositorio y avisa a tu equipo de seguridad.",
				}
				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
			} else {
				ec.add(fmt.Errorf("%s: %w", p.Name, err))
				return
			}
		}
		files, _ := registry.ExtractTarball(data, 2<<20, 5000)
		p.Meta.ScriptHits = rules.ScanTarball(files, p.Meta.InstallScripts)
	})
	return findings, ec.warn("tarballs npm"), ec.n > 0
}

func asIntegrity(err error, target **registry.ErrIntegrity) bool {
	ie, ok := err.(*registry.ErrIntegrity)
	if ok {
		*target = ie
	}
	return ok
}
