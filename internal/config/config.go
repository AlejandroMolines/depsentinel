// Package config carga y valida .depsentinel.json y los endpoints configurables por entorno.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// FileName es el nombre del fichero de configuración del proyecto.
const FileName = ".depsentinel.json"

// Network agrupa opciones de red.
type Network struct {
	TimeoutSeconds int  `json:"timeout_seconds"`
	Concurrency    int  `json:"concurrency"`
	Offline        bool `json:"offline"`
}

// Config es la configuración de un proyecto.
type Config struct {
	Version            int      `json:"version"`
	Ecosystems         []string `json:"ecosystems,omitempty"`
	FailOn             string   `json:"fail_on"`
	IncludeDev         bool     `json:"include_dev"`
	IgnorePaths        []string `json:"ignore_paths,omitempty"`
	AllowlistFile      string   `json:"allowlist_file"`
	DisabledRules      []string `json:"disabled_rules,omitempty"`
	UnmaintainedDays   int      `json:"unmaintained_days"`
	MinReleaseAgeHours int      `json:"min_release_age_hours"`
	FeedURL            string   `json:"feed_url,omitempty"`
	FeedPublicKey      string   `json:"feed_public_key,omitempty"`
	Network            Network  `json:"network"`
}

// KnownRules lista todas las reglas (se usan para validar disabled_rules y en la documentación).
var KnownRules = []string{
	"malicious", "vulnerability", "typosquat", "install-script", "suspicious-script",
	"unmaintained", "deprecated", "yanked", "fresh-release", "provenance", "version-anomaly",
	"unpinned", "source", "index-url", "integrity",
	"image-tag", "image-digest", "remote-script", "remote-add", "secret-in-image", "root-user",
	"action-pinning", "workflow-injection", "pwn-request", "workflow-permissions",
}

// Default devuelve la configuración por defecto.
func Default() *Config {
	return &Config{
		Version:            1,
		FailOn:             "high",
		IncludeDev:         true,
		AllowlistFile:      ".depsentinel/allowlist.json",
		UnmaintainedDays:   730,
		MinReleaseAgeHours: 72,
		Network:            Network{TimeoutSeconds: 20, Concurrency: 8},
	}
}

// Load lee un fichero de configuración sobre los valores por defecto (rechaza campos desconocidos).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Find busca .depsentinel.json en dir y en sus directorios padre (hasta 6 niveles).
func Find(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for i := 0; i < 6; i++ {
		p := filepath.Join(abs, FileName)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return ""
}

// Validate comprueba que los valores son coherentes.
func (c *Config) Validate() error {
	if _, err := model.ParseSeverity(c.FailOn); err != nil {
		return fmt.Errorf("fail_on: %w", err)
	}
	for _, e := range c.Ecosystems {
		if strings.EqualFold(e, "auto") || strings.EqualFold(e, "all") {
			continue
		}
		if _, ok := model.ParseEcosystem(e); !ok {
			return fmt.Errorf("ecosystems: ecosistema desconocido %q", e)
		}
	}
	known := map[string]bool{}
	for _, r := range KnownRules {
		known[r] = true
	}
	for _, r := range c.DisabledRules {
		if !known[r] {
			return fmt.Errorf("disabled_rules: regla desconocida %q (reglas válidas: %s)", r, strings.Join(KnownRules, ", "))
		}
	}
	if c.Network.TimeoutSeconds <= 0 || c.Network.TimeoutSeconds > 300 {
		return fmt.Errorf("network.timeout_seconds debe estar entre 1 y 300")
	}
	if c.Network.Concurrency < 1 || c.Network.Concurrency > 64 {
		return fmt.Errorf("network.concurrency debe estar entre 1 y 64")
	}
	if c.UnmaintainedDays < 0 || c.MinReleaseAgeHours < 0 {
		return fmt.Errorf("los umbrales no pueden ser negativos")
	}
	return nil
}

// RuleEnabled indica si una regla está activa.
func (c *Config) RuleEnabled(rule string) bool {
	if c == nil {
		return true
	}
	for _, r := range c.DisabledRules {
		if r == rule {
			return false
		}
	}
	return true
}

// Save escribe la configuración con sangría.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Endpoints son las URLs base de los servicios externos (sobrescribibles por entorno).
type Endpoints struct {
	OSV, NPM, PyPI, GoProxy, GitHub, Feed string
}

// EndpointsFromEnv lee DEPSENTINEL_*_URL para usar mirrors internos o servidores de prueba.
func EndpointsFromEnv() Endpoints {
	return Endpoints{
		OSV:     os.Getenv("DEPSENTINEL_OSV_URL"),
		NPM:     os.Getenv("DEPSENTINEL_NPM_URL"),
		PyPI:    os.Getenv("DEPSENTINEL_PYPI_URL"),
		GoProxy: os.Getenv("DEPSENTINEL_GOPROXY_URL"),
		GitHub:  os.Getenv("DEPSENTINEL_GITHUB_API_URL"),
		Feed:    os.Getenv("DEPSENTINEL_FEED_URL"),
	}
}

// SortedRules devuelve las reglas conocidas ordenadas (para ayuda y docs).
func SortedRules() []string {
	out := append([]string(nil), KnownRules...)
	sort.Strings(out)
	return out
}
