package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAndRoundTrip(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.FailOn != "high" || !c.IncludeDev || c.UnmaintainedDays != 730 || c.MinReleaseAgeHours != 72 {
		t.Errorf("valores por defecto: %+v", c)
	}
	path := filepath.Join(t.TempDir(), FileName)
	c.DisabledRules = []string{"typosquat"}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RuleEnabled("typosquat") || !loaded.RuleEnabled("malicious") {
		t.Error("disabled_rules no se respeta")
	}
	var nilCfg *Config
	if !nilCfg.RuleEnabled("anything") {
		t.Error("una configuración nil activa todas las reglas")
	}
}

func TestLoadRejectsMistakes(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, FileName)
		_ = os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	cases := map[string]string{
		`{"fail_on":"urgente"}`:                               "severity",
		`{"disabled_rules":["typosquating"]}`:                 "regla desconocida",
		`{"ecosystems":["cobol"]}`:                            "ecosistema",
		`{"network":{"timeout_seconds":0}}`:                   "timeout",
		`{"network":{"concurrency":500,"timeout_seconds":5}}`: "concurrency",
		`{"fail_on":"high","campo_raro":1}`:                   "unknown field",
	}
	for body, want := range cases {
		if _, err := Load(write(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, esperaba que mencione %q", body, err, want)
		}
	}
	// parcial: lo que no se indica queda en los valores por defecto
	c, err := Load(write(`{"fail_on":"critical"}`))
	if err != nil || c.FailOn != "critical" || c.Network.Concurrency != 8 {
		t.Errorf("configuración parcial: %+v %v", c, err)
	}
}

func TestFindWalksUp(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	_ = os.MkdirAll(deep, 0o755)
	if Find(deep) != "" {
		t.Error("sin fichero no debe encontrar nada")
	}
	_ = os.WriteFile(filepath.Join(root, "a", FileName), []byte(`{}`), 0o644)
	if got := Find(deep); got != filepath.Join(root, "a", FileName) {
		t.Errorf("Find = %q", got)
	}
}

func TestEndpointsFromEnv(t *testing.T) {
	t.Setenv("DEPSENTINEL_OSV_URL", "http://127.0.0.1:1")
	t.Setenv("DEPSENTINEL_NPM_URL", "http://127.0.0.1:2")
	e := EndpointsFromEnv()
	if e.OSV != "http://127.0.0.1:1" || e.NPM != "http://127.0.0.1:2" || e.PyPI != "" {
		t.Errorf("%+v", e)
	}
}
