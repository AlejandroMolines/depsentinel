package fix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/engine"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/registry"
)

const pkgJSON = `{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.15",
    "axios": "~0.21.0"
  },
  "devDependencies": {
    "minimist": "1.2.0"
  },
  "overrides": {
    "lodash": "^4.17.15"
  }
}
`

func TestBumpPackageJSONKeepsFormatting(t *testing.T) {
	out, err := bumpPackageJSON([]byte(pkgJSON), []Action{
		{Package: "lodash", From: "^4.17.15", To: "^4.17.21"},
		{Package: "minimist", From: "1.2.0", To: "1.2.6"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	want := strings.NewReplacer(`"lodash": "^4.17.15",
    "axios"`, `"lodash": "^4.17.21",
    "axios"`, `"minimist": "1.2.0"`, `"minimist": "1.2.6"`).Replace(pkgJSON)
	if s != want {
		t.Errorf("solo debe cambiar esas dos líneas (overrides intacto):\n%s", s)
	}
	if !json.Valid(out) {
		t.Error("JSON inválido")
	}
	if _, err := bumpPackageJSON([]byte(pkgJSON), []Action{{Package: "no-esta", From: "1", To: "2"}}); err == nil {
		t.Error("una dependencia ausente debe ser un error")
	}
	if _, err := bumpPackageJSON([]byte(pkgJSON), []Action{{Package: "lodash", From: "9.9.9", To: "1"}}); err == nil {
		t.Error("un rango que no coincide debe ser un error")
	}
}

func TestEditLines(t *testing.T) {
	src := "requests==2.25.0\r\nflask===1.0\r\nsafe==1.0 --hash=sha256:abc\r\n"
	out, err := editLines([]byte(src), []Action{
		{Kind: "bump-requirement", Package: "requests", From: "2.25.0", To: "2.31.0", Line: 1},
		{Kind: "bump-requirement", Package: "flask", From: "1.0", To: "2.3.0", Line: 2},
	})
	if err != nil || string(out) != "requests==2.31.0\r\nflask===2.3.0\r\nsafe==1.0 --hash=sha256:abc\r\n" {
		t.Errorf("%q %v", out, err)
	}
	if _, err := editLines([]byte(src), []Action{{Kind: "bump-requirement", Package: "safe", From: "1.0", To: "2.0", Line: 3}}); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Errorf("las líneas con hashes no se tocan: %v", err)
	}
	wf := "steps:\n  - uses: actions/checkout@v4\n  - uses: 'github/codeql-action/init@v3'\n  - uses: a/b@v1 # nota\n"
	sha := strings.Repeat("a", 40)
	out, err = editLines([]byte(wf), []Action{
		{Kind: "pin-action", Package: "actions/checkout", From: "v4", To: sha, Line: 2},
		{Kind: "pin-action", Package: "github/codeql-action", From: "v3", To: sha, Line: 3},
		{Kind: "pin-action", Package: "a/b", From: "v1", To: sha, Line: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "steps:\n  - uses: actions/checkout@" + sha + " # v4\n  - uses: 'github/codeql-action/init@" + sha + "' # v3\n  - uses: a/b@" + sha + " # v1 # nota\n"
	if string(out) != want {
		t.Errorf("pin de acciones:\n%s\nquiero:\n%s", out, want)
	}
}

func TestBuildPlanAndApply(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644))
	must(os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.25.0\npyyaml==5.3.1\n"), 0o644))
	must(os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755))
	must(os.WriteFile(filepath.Join(dir, ".github", "workflows", "ci.yml"), []byte("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"), 0o644))

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/actions/checkout/commits/v4" {
			_, _ = w.Write([]byte(`{"sha":"11bd71901bbe5b1630ceea73d27597364c9af683"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer gh.Close()
	hc := httpx.New(5*time.Second, false)
	hc.Retries = 0

	pkgs := []*model.Package{
		{Ecosystem: model.NPM, Name: "lodash", Version: "4.17.15", Direct: true, Source: "package-lock.json"},
		{Ecosystem: model.NPM, Name: "minimist", Version: "1.2.0", Direct: true, Dev: true, Source: "package-lock.json"},
		{Ecosystem: model.NPM, Name: "debug", Version: "2.6.8", Source: "package-lock.json"},
		{Ecosystem: model.NPM, Name: "express", Version: "4.17.1", Direct: true, Source: "package-lock.json", DependsOn: []string{"npm:debug@2.6.8"}},
	}
	rep := &model.Report{Findings: []model.Finding{
		{ID: "GHSA-1", Rule: "vulnerability", Ecosystem: model.NPM, Package: "lodash", Version: "4.17.15", FixedIn: "4.17.19", Severity: model.SeverityHigh},
		{ID: "GHSA-2", Rule: "vulnerability", Ecosystem: model.NPM, Package: "lodash", Version: "4.17.15", FixedIn: "4.17.21", Severity: model.SeverityHigh},
		{ID: "GHSA-3", Rule: "vulnerability", Ecosystem: model.NPM, Package: "minimist", Version: "1.2.0", FixedIn: "1.2.6", Severity: model.SeverityCritical},
		{ID: "GHSA-4", Rule: "vulnerability", Ecosystem: model.NPM, Package: "debug", Version: "2.6.8", FixedIn: "2.6.9", Severity: model.SeverityHigh},
		{ID: "GHSA-5", Rule: "vulnerability", Ecosystem: model.PyPI, Package: "requests", Version: "2.25.0", FixedIn: "2.31.0", Source: "requirements.txt", Line: 1, Severity: model.SeverityHigh},
		{ID: "GHSA-6", Rule: "vulnerability", Ecosystem: model.PyPI, Package: "django", Version: "3.0", FixedIn: "3.2", Source: "poetry.lock", Severity: model.SeverityHigh},
		{ID: "GHSA-7", Rule: "vulnerability", Ecosystem: model.Go, Package: "golang.org/x/text", Version: "v0.3.7", FixedIn: "v0.3.8", Severity: model.SeverityHigh},
		{ID: "DS-ACTIONS-TAG", Rule: "action-pinning", Ecosystem: model.Actions, Package: "actions/checkout", Version: "v4", Source: ".github/workflows/ci.yml", Line: 4},
		{ID: "DS-DOCKER-LATEST", Rule: "image-tag", Ecosystem: model.Docker, Package: "node", Version: "latest", Source: "Dockerfile", Line: 1},
		{ID: "DS-0001", Rule: "malicious", Ecosystem: model.NPM, Package: "event-stream", Version: "3.3.6"},
	}}
	res := &engine.Result{Report: rep, Inventory: &engine.Inventory{BaseDir: dir, Packages: pkgs}}
	plan, err := BuildPlan(context.Background(), Options{BaseDir: dir, GitHub: registry.NewGitHub(hc, gh.URL)}, res)
	if err != nil {
		t.Fatal(err)
	}
	var desc []string
	for _, e := range plan.Edits {
		desc = append(desc, describe(e))
	}
	got := strings.Join(desc, " | ")
	for _, want := range []string{`lodash: "^4.17.15" → "^4.17.21"`, `minimist: "1.2.0" → "1.2.6"`, "requests: ==2.25.0 → ==2.31.0", "actions/checkout: @v4 → @11bd71901bbe…"} {
		if !strings.Contains(got, want) {
			t.Errorf("falta %q en: %s", want, got)
		}
	}
	manual := ""
	for _, m := range plan.Manual {
		manual += m.Package + ":" + m.Command + " | " + m.Note + "\n"
	}
	for _, want := range []string{"debug:npm update debug", "la trae express@4.17.1", "overrides", "poetry update django", "go get golang.org/x/text@v0.3.8", "docker buildx imagetools inspect node:", "npm uninstall event-stream"} {
		if !strings.Contains(manual, want) {
			t.Errorf("manual: falta %q en:\n%s", want, manual)
		}
	}

	changed, err := plan.Apply(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 {
		t.Errorf("ficheros modificados: %v", changed)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "package.json"))
	if !strings.Contains(string(b), `"lodash": "^4.17.21"`) || !strings.Contains(string(b), `"minimist": "1.2.6"`) || !strings.Contains(string(b), `"axios": "~0.21.0"`) {
		t.Errorf("package.json: %s", b)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "requirements.txt"))
	if string(b) != "requests==2.31.0\npyyaml==5.3.1\n" {
		t.Errorf("requirements.txt: %q", b)
	}
	b, _ = os.ReadFile(filepath.Join(dir, ".github", "workflows", "ci.yml"))
	if !strings.Contains(string(b), "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4") {
		t.Errorf("workflow: %s", b)
	}

	// sin conexión: las acciones pasan a manual
	plan, _ = BuildPlan(context.Background(), Options{BaseDir: dir}, res)
	for _, e := range plan.Edits {
		if e.Kind == "pin-action" {
			t.Error("sin conexión no se puede resolver el SHA")
		}
	}
}
