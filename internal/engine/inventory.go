// Package engine orquesta un escaneo: detección de manifiestos, consultas externas, reglas y allowlist.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/allowlist"
	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/config"
	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/scanner"
)

// Options controla un escaneo.
type Options struct {
	Dir        string
	Ecosystems []model.Ecosystem // vacío = detectar automáticamente
	NPMLock    string            // fuerza este lockfile de npm (ruta relativa a Dir o absoluta)
	Offline    bool
	NoRegistry bool
	NoOSV      bool
	Deep       bool
	ProdOnly   bool
	Config     *config.Config
	Allowlist  *allowlist.List
	Store      *db.Store
	Cache      *cache.Cache
	HTTP       *httpx.Client
	Endpoints  config.Endpoints
	Now        func() time.Time
	Log        func(format string, args ...any)
}

func (o *Options) defaults() {
	if o.Config == nil {
		o.Config = config.Default()
	}
	if o.Dir == "" {
		o.Dir = "."
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Cache == nil {
		o.Cache = cache.Default()
	}
	if o.Store == nil {
		s, err := db.Load(o.Cache.Dir())
		if err != nil {
			s, _ = db.Load("")
		}
		o.Store = s
	}
	if o.HTTP == nil {
		o.HTTP = httpx.New(time.Duration(o.Config.Network.TimeoutSeconds)*time.Second, o.Offline)
	}
	if o.Endpoints == (config.Endpoints{}) {
		o.Endpoints = config.EndpointsFromEnv()
	}
	if o.Config.Network.Offline {
		o.Offline = true
		o.HTTP.Offline = true
	}
}

// Inventory es el resultado de leer los manifiestos (sin red).
type Inventory struct {
	BaseDir     string
	Ecosystems  []model.Ecosystem
	Sources     []string
	Packages    []*model.Package
	Findings    []model.Finding
	Warnings    []string
	RootName    string
	RootVersion string
	ParseErrors int
}

func wantedSet(list []model.Ecosystem, cfg *config.Config) map[model.Ecosystem]bool {
	want := map[model.Ecosystem]bool{}
	for _, e := range list {
		want[e] = true
	}
	if len(want) == 0 && cfg != nil {
		for _, s := range cfg.Ecosystems {
			if e, ok := model.ParseEcosystem(s); ok {
				want[e] = true
			}
		}
	}
	return want
}

// BuildInventory detecta y analiza los manifiestos soportados.
func BuildInventory(o Options) (*Inventory, error) {
	o.defaults()
	abs, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("no puedo leer %s: %w", o.Dir, err)
	}
	base := abs
	if !st.IsDir() {
		base = filepath.Dir(abs)
	}
	files, err := scanner.Detect(abs, o.Config.IgnorePaths)
	if err != nil {
		return nil, err
	}
	want := wantedSet(o.Ecosystems, o.Config)
	inv := &Inventory{BaseDir: base}

	if o.NPMLock != "" {
		lock := o.NPMLock
		if !filepath.IsAbs(lock) {
			lock = filepath.Join(base, lock)
		}
		if _, err := os.Stat(lock); err != nil {
			return nil, fmt.Errorf("no encuentro el lockfile %s", o.NPMLock)
		}
		rel, err := filepath.Rel(base, lock)
		if err != nil {
			rel = filepath.Base(lock)
		}
		files[model.NPM] = []string{filepath.ToSlash(rel)}
		if len(want) == 0 {
			want[model.NPM] = true
		}
	}

	var raw []*model.Package
	for _, eco := range model.AllEcosystems {
		if len(want) > 0 && !want[eco] {
			continue
		}
		list := files[eco]
		if len(list) == 0 {
			continue
		}
		inv.Ecosystems = append(inv.Ecosystems, eco)
		for _, rel := range list {
			res, err := scanner.Parse(eco, filepath.Join(base, filepath.FromSlash(rel)), rel)
			if err != nil {
				inv.ParseErrors++
				inv.Warnings = append(inv.Warnings, fmt.Sprintf("No se pudo leer %s: %v", rel, err))
				continue
			}
			inv.Sources = append(inv.Sources, rel)
			raw = append(raw, res.Packages...)
			inv.Findings = append(inv.Findings, res.Findings...)
			inv.Warnings = append(inv.Warnings, res.Warnings...)
			if eco == model.NPM && inv.RootName == "" {
				inv.RootName, inv.RootVersion = res.RootName, res.RootVersion
			}
			if eco == model.Go && inv.RootName == "" {
				inv.RootName = res.RootName
			}
		}
	}
	inv.Packages = mergePackages(raw)
	if o.ProdOnly || !o.Config.IncludeDev {
		inv.Packages, inv.Findings = dropDev(inv.Packages, inv.Findings)
	}
	return inv, nil
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			a = append(a, v)
		}
	}
	return a
}

// mergePackages fusiona apariciones repetidas del mismo paquete@versión (por ejemplo en node_modules anidados).
func mergePackages(in []*model.Package) []*model.Package {
	idx := map[string]*model.Package{}
	var order []string
	for _, p := range in {
		k := p.Key()
		q, ok := idx[k]
		if !ok {
			cp := *p
			cp.Locations = append([]string(nil), p.Locations...)
			cp.DependsOn = append([]string(nil), p.DependsOn...)
			idx[k] = &cp
			order = append(order, k)
			continue
		}
		q.Direct = q.Direct || p.Direct
		q.Dev = q.Dev && p.Dev
		q.Optional = q.Optional && p.Optional
		q.HasInstallScript = q.HasInstallScript || p.HasInstallScript
		q.Private = q.Private || p.Private
		q.Unpinned = q.Unpinned && p.Unpinned
		q.Locations = union(q.Locations, p.Locations)
		q.DependsOn = union(q.DependsOn, p.DependsOn)
		if q.Integrity == "" {
			q.Integrity = p.Integrity
		}
		if q.Resolved == "" {
			q.Resolved = p.Resolved
		}
	}
	out := make([]*model.Package, 0, len(order))
	for _, k := range order {
		sort.Strings(idx[k].DependsOn)
		out = append(out, idx[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out
}

func dropDev(pkgs []*model.Package, findings []model.Finding) ([]*model.Package, []model.Finding) {
	drop := map[string]bool{}
	var keep []*model.Package
	for _, p := range pkgs {
		if p.Dev {
			drop[p.Key()] = true
			continue
		}
		keep = append(keep, p)
	}
	var fkeep []model.Finding
	for _, f := range findings {
		if drop[f.PackageKey()] {
			continue
		}
		fkeep = append(fkeep, f)
	}
	return keep, fkeep
}

// describeEcosystems devuelve los nombres para mostrar.
func describeEcosystems(es []model.Ecosystem) string {
	var s []string
	for _, e := range es {
		s = append(s, e.Label())
	}
	return strings.Join(s, ", ")
}
