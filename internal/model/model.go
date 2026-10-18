// Package model define los tipos compartidos por todo DepSentinel.
package model

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Ecosystem identifica el gestor de paquetes o tipo de artefacto analizado.
type Ecosystem string

const (
	NPM     Ecosystem = "npm"
	PyPI    Ecosystem = "pypi"
	Go      Ecosystem = "go"
	Docker  Ecosystem = "docker"
	Actions Ecosystem = "actions"
)

// AllEcosystems lista los ecosistemas soportados, en orden de presentación.
var AllEcosystems = []Ecosystem{NPM, PyPI, Go, Docker, Actions}

// OSV devuelve el nombre del ecosistema en la base OSV ("" si OSV no lo cubre).
func (e Ecosystem) OSV() string {
	switch e {
	case NPM:
		return "npm"
	case PyPI:
		return "PyPI"
	case Go:
		return "Go"
	case Actions:
		return "GitHub Actions"
	}
	return ""
}

// Label devuelve un nombre legible del ecosistema.
func (e Ecosystem) Label() string {
	switch e {
	case NPM:
		return "npm"
	case PyPI:
		return "PyPI"
	case Go:
		return "Go"
	case Docker:
		return "Docker"
	case Actions:
		return "GitHub Actions"
	}
	return string(e)
}

// ParseEcosystem acepta el nombre canónico y varios alias comunes.
func ParseEcosystem(s string) (Ecosystem, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "npm", "node", "nodejs", "js":
		return NPM, true
	case "pypi", "pip", "python", "py":
		return PyPI, true
	case "go", "golang", "gomod":
		return Go, true
	case "docker", "container", "containers", "oci":
		return Docker, true
	case "actions", "github-actions", "githubactions", "gha":
		return Actions, true
	}
	return "", false
}

// Severity es el nivel de riesgo de un hallazgo.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String devuelve el nombre estable (en inglés) usado en JSON y flags.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "none"
}

// Label devuelve el nombre en español para mostrar a personas.
func (s Severity) Label() string {
	switch s {
	case SeverityLow:
		return "bajo"
	case SeverityMedium:
		return "medio"
	case SeverityHigh:
		return "alto"
	case SeverityCritical:
		return "crítico"
	}
	return "ninguno"
}

// ParseSeverity acepta nombres en inglés y español.
func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none", "ninguno", "off":
		return SeverityNone, nil
	case "low", "bajo", "baja":
		return SeverityLow, nil
	case "medium", "moderate", "medio", "media":
		return SeverityMedium, nil
	case "high", "alto", "alta":
		return SeverityHigh, nil
	case "critical", "crit", "critico", "crítico", "critica", "crítica":
		return SeverityCritical, nil
	}
	return SeverityNone, fmt.Errorf("severidad desconocida %q (usa: low, medium, high, critical o none)", v)
}

// ParseSeverityList parsea una lista separada por comas ("high,critical").
func ParseSeverityList(v string) ([]Severity, error) {
	var out []Severity
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		s, err := ParseSeverity(part)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// MarshalJSON serializa la severidad como cadena.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON lee la severidad desde una cadena.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	p, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = p
	return nil
}

// Package es una dependencia (o artefacto) detectada en un manifiesto.
type Package struct {
	Ecosystem        Ecosystem `json:"ecosystem"`
	Name             string    `json:"name"`
	Version          string    `json:"version,omitempty"`
	Direct           bool      `json:"direct,omitempty"`
	Dev              bool      `json:"dev,omitempty"`
	Optional         bool      `json:"optional,omitempty"`
	Source           string    `json:"source,omitempty"`
	Resolved         string    `json:"resolved,omitempty"`
	Integrity        string    `json:"integrity,omitempty"`
	HasInstallScript bool      `json:"has_install_script,omitempty"`
	// Private indica que el paquete no viene del registry público: no se consulta fuera.
	Private bool `json:"private,omitempty"`
	// Unpinned es verdadero cuando el manifiesto no fija una versión exacta.
	Unpinned  bool     `json:"unpinned,omitempty"`
	Line      int      `json:"line,omitempty"`
	Locations []string `json:"-"`
	// DependsOn contiene las claves (Key) de las dependencias directas de este paquete.
	DependsOn []string `json:"-"`
	Meta      *Meta    `json:"meta,omitempty"`
}

// Key identifica de forma única ecosistema+nombre+versión.
func (p *Package) Key() string { return PackageKey(p.Ecosystem, p.Name, p.Version) }

// PackageKey construye la clave única de un paquete.
func PackageKey(eco Ecosystem, name, version string) string {
	return string(eco) + ":" + name + "@" + version
}

// Meta agrupa los datos obtenidos de los registries públicos.
type Meta struct {
	Latest            string            `json:"latest,omitempty"`
	LastRelease       *time.Time        `json:"last_release,omitempty"`
	Created           *time.Time        `json:"created,omitempty"`
	VersionCount      int               `json:"version_count,omitempty"`
	Published         *time.Time        `json:"published,omitempty"`
	Publisher         string            `json:"publisher,omitempty"`
	PreviousVersion   string            `json:"previous_version,omitempty"`
	PreviousPublisher string            `json:"previous_publisher,omitempty"`
	Maintainers       []string          `json:"maintainers,omitempty"`
	NewMaintainers    []string          `json:"new_maintainers,omitempty"`
	Deprecated        string            `json:"deprecated,omitempty"`
	HasInstallScript  bool              `json:"has_install_script,omitempty"`
	Yanked            bool              `json:"yanked,omitempty"`
	YankedReason      string            `json:"yanked_reason,omitempty"`
	InstallScripts    map[string]string `json:"install_scripts,omitempty"`
	SdistOnly         bool              `json:"sdist_only,omitempty"`
	Repository        string            `json:"repository,omitempty"`
	License           string            `json:"license,omitempty"`
	// PackageMissing: el paquete no existe en el registry público.
	PackageMissing bool `json:"package_missing,omitempty"`
	// VersionMissing: el paquete existe pero no esa versión.
	VersionMissing bool `json:"version_missing,omitempty"`
	// Deep indica que se obtuvo información completa (publicador, scripts, fechas).
	Deep bool `json:"deep,omitempty"`
	// Tarball es la URL del artefacto en el registry (solo npm, modo deep).
	Tarball string `json:"tarball,omitempty"`
	// RegistryIntegrity es el hash SRI que publica el registry para este artefacto.
	RegistryIntegrity string `json:"registry_integrity,omitempty"`
	// ScriptHits son los indicios encontrados al inspeccionar los scripts de instalación.
	ScriptHits []ScriptHit `json:"script_hits,omitempty"`
}

// ScriptHit es un indicio detectado en un script de instalación.
type ScriptHit struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Why      string   `json:"why"`
	Script   string   `json:"script,omitempty"`
	File     string   `json:"file,omitempty"`
	Match    string   `json:"match,omitempty"`
}

// Finding es un problema detectado.
type Finding struct {
	ID         string       `json:"id"`
	Rule       string       `json:"rule"`
	Severity   Severity     `json:"severity"`
	Ecosystem  Ecosystem    `json:"ecosystem"`
	Package    string       `json:"package"`
	Version    string       `json:"version,omitempty"`
	Title      string       `json:"title"`
	Detail     string       `json:"detail,omitempty"`
	Fix        string       `json:"fix,omitempty"`
	FixedIn    string       `json:"fixed_in,omitempty"`
	Aliases    []string     `json:"aliases,omitempty"`
	References []string     `json:"references,omitempty"`
	Source     string       `json:"source,omitempty"`
	Line       int          `json:"line,omitempty"`
	Allowed    *AllowedInfo `json:"allowed,omitempty"`
}

// AllowedInfo describe por qué un hallazgo está en la lista blanca.
type AllowedInfo struct {
	Reason  string `json:"reason"`
	Added   string `json:"added,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// PackageKey devuelve la clave del paquete al que pertenece el hallazgo.
func (f Finding) PackageKey() string { return PackageKey(f.Ecosystem, f.Package, f.Version) }

// SortFindings ordena por severidad descendente y después por ecosistema, paquete y regla.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.ID < b.ID
	})
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// NormalizeName normaliza un nombre según las reglas de cada ecosistema.
func NormalizeName(eco Ecosystem, name string) string {
	switch eco {
	case PyPI:
		return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
	case NPM:
		return strings.ToLower(name)
	case Docker:
		n := strings.ToLower(name)
		for _, p := range []string{"index.docker.io/", "registry-1.docker.io/", "docker.io/"} {
			n = strings.TrimPrefix(n, p)
		}
		return strings.TrimPrefix(n, "library/")
	case Actions:
		return strings.ToLower(name)
	}
	return name
}

// Highest devuelve la mayor severidad de una lista de hallazgos.
func Highest(fs []Finding) Severity {
	var max Severity
	for _, f := range fs {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// RiskLevel traduce una severidad máxima al nivel global (bajo, medio, alto, crítico).
func RiskLevel(s Severity) string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	}
	return "low"
}

// RiskScore calcula un score 0-100: el peor hallazgo pesa más y el resto suma poco.
func RiskScore(fs []Finding) int {
	weights := make([]int, 0, len(fs))
	for _, f := range fs {
		switch f.Severity {
		case SeverityCritical:
			weights = append(weights, 90)
		case SeverityHigh:
			weights = append(weights, 60)
		case SeverityMedium:
			weights = append(weights, 30)
		case SeverityLow:
			weights = append(weights, 10)
		}
	}
	if len(weights) == 0 {
		return 0
	}
	sort.Sort(sort.Reverse(sort.IntSlice(weights)))
	score := weights[0]
	for _, w := range weights[1:] {
		score += w / 4
	}
	if score > 100 {
		score = 100
	}
	return score
}

// Recommendation resume qué hacer con un paquete: use, update, review o avoid.
func Recommendation(fs []Finding) string {
	rec := "use"
	for _, f := range fs {
		switch {
		case f.Rule == "malicious" || (f.Severity == SeverityCritical && f.FixedIn == ""):
			return "avoid"
		case f.Severity >= SeverityHigh && f.FixedIn != "":
			rec = "update"
		case f.Severity >= SeverityMedium && rec == "use":
			rec = "review"
		}
	}
	return rec
}

// Summary agrega los números globales de un escaneo.
type Summary struct {
	Packages    int            `json:"packages"`
	Findings    int            `json:"findings"`
	Suppressed  int            `json:"suppressed"`
	BySeverity  map[string]int `json:"by_severity"`
	ByEcosystem map[string]int `json:"by_ecosystem"`
	RiskLevel   string         `json:"risk_level"`
}

// PackageReport es la vista por paquete del informe.
type PackageReport struct {
	Ecosystem      Ecosystem `json:"ecosystem"`
	Name           string    `json:"name"`
	Version        string    `json:"version,omitempty"`
	Direct         bool      `json:"direct,omitempty"`
	Dev            bool      `json:"dev,omitempty"`
	Source         string    `json:"source,omitempty"`
	RiskScore      int       `json:"risk_score"`
	RiskLevel      string    `json:"risk_level"`
	Recommendation string    `json:"recommendation"`
	Findings       int       `json:"findings"`
	Meta           *Meta     `json:"meta,omitempty"`
}

// SchemaVersion es la versión del formato JSON del informe.
const SchemaVersion = 1

// Report es el resultado completo de un escaneo.
type Report struct {
	Tool          string          `json:"tool"`
	Version       string          `json:"version"`
	SchemaVersion int             `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Target        string          `json:"target"`
	Ecosystems    []Ecosystem     `json:"ecosystems"`
	Sources       []string        `json:"sources"`
	Offline       bool            `json:"offline"`
	Incomplete    bool            `json:"incomplete"`
	Summary       Summary         `json:"summary"`
	Packages      []PackageReport `json:"packages"`
	Findings      []Finding       `json:"findings"`
	Suppressed    []Finding       `json:"suppressed,omitempty"`
	Warnings      []string        `json:"warnings,omitempty"`
}

// Count devuelve cuántos hallazgos tienen al menos la severidad indicada.
func (r *Report) Count(min Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity >= min {
			n++
		}
	}
	return n
}

// Highest devuelve la mayor severidad de los hallazgos activos.
func (r *Report) Highest() Severity { return Highest(r.Findings) }

// BuildSummary rellena Summary, Packages y ordena los hallazgos.
func (r *Report) BuildSummary(pkgs []*Package) {
	SortFindings(r.Findings)
	SortFindings(r.Suppressed)
	by := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, f := range r.Findings {
		by[f.Severity.String()]++
	}
	byEco := map[string]int{}
	grouped := map[string][]Finding{}
	for _, f := range r.Findings {
		grouped[f.PackageKey()] = append(grouped[f.PackageKey()], f)
	}
	r.Packages = make([]PackageReport, 0, len(pkgs))
	for _, p := range pkgs {
		byEco[string(p.Ecosystem)]++
		fs := grouped[p.Key()]
		r.Packages = append(r.Packages, PackageReport{
			Ecosystem:      p.Ecosystem,
			Name:           p.Name,
			Version:        p.Version,
			Direct:         p.Direct,
			Dev:            p.Dev,
			Source:         p.Source,
			RiskScore:      RiskScore(fs),
			RiskLevel:      RiskLevel(Highest(fs)),
			Recommendation: Recommendation(fs),
			Findings:       len(fs),
			Meta:           p.Meta,
		})
	}
	sort.SliceStable(r.Packages, func(i, j int) bool {
		a, b := r.Packages[i], r.Packages[j]
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	r.Summary = Summary{
		Packages:    len(pkgs),
		Findings:    len(r.Findings),
		Suppressed:  len(r.Suppressed),
		BySeverity:  by,
		ByEcosystem: byEco,
		RiskLevel:   RiskLevel(Highest(r.Findings)),
	}
}
