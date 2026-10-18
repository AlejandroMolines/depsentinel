package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	app := &App{Stdout: &out, Stderr: &errb}
	code := app.Run(context.Background(), args)
	return code, out.String(), errb.String()
}

func setup(t *testing.T) string {
	t.Helper()
	t.Setenv("DEPSENTINEL_CACHE_DIR", t.TempDir())
	t.Setenv("DEPSENTINEL_OFFLINE", "1")
	t.Setenv("NO_COLOR", "1")
	t.Setenv("GITHUB_ACTIONS", "")
	dir := t.TempDir()
	lock := `{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{
	 "":{"name":"demo","dependencies":{"event-stream":"3.3.6","lodash":"4.17.15"}},
	 "node_modules/event-stream":{"version":"3.3.6","resolved":"https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz","integrity":"sha512-AAAA"},
	 "node_modules/lodash":{"version":"4.17.15","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz","integrity":"sha512-BBBB"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"demo","dependencies":{"event-stream":"3.3.6","lodash":"4.17.15"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBasics(t *testing.T) {
	setup(t)
	if code, out, _ := run(t, "version"); code != 0 || !strings.Contains(out, "depsentinel") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ := run(t, "help"); code != 0 || !strings.Contains(out, "Commands:") {
		t.Errorf("help: %d", code)
	}
	if code, _, errb := run(t, "no-existe"); code != ExitUsage || !strings.Contains(errb, "Unknown") {
		t.Errorf("comando desconocido: %d %q", code, errb)
	}
	if code, _, _ := run(t); code != ExitUsage {
		t.Error("sin argumentos: uso incorrecto")
	}
}

func TestScanExitCodes(t *testing.T) {
	dir := setup(t)
	code, out, _ := run(t, "scan", dir, "--no-color")
	if code != 0 || !strings.Contains(out, "event-stream@3.3.6") || !strings.Contains(out, "critical") {
		t.Errorf("scan sin umbral no falla: %d\n%s", code, out)
	}
	if code, _, _ := run(t, "scan", dir, "--ci"); code != ExitFindings {
		t.Errorf("--ci usa fail_on=high por defecto y hay un crítico: %d", code)
	}
	if code, _, _ := run(t, "scan", dir, "--ci", "--fail-on", "none"); code != 0 {
		t.Errorf("fail-on none: %d", code)
	}
	if code, _, _ := run(t, "scan", "--fail-on", "critical", dir); code != ExitFindings {
		t.Errorf("flags antes o después de la ruta: %d", code)
	}
	if code, _, errb := run(t, "scan", dir, "--fail-on", "raro"); code != ExitUsage || !strings.Contains(errb, "severity") {
		t.Errorf("severidad inválida: %d %q", code, errb)
	}
	if code, _, errb := run(t, "scan", dir, "--ecosystem", "pypi"); code != ExitUsage || !strings.Contains(errb, "no manifests found") {
		t.Errorf("ecosistema sin manifiestos: %d %q", code, errb)
	}
	if code, _, errb := run(t, "scan", dir, "--format", "xml"); code != ExitUsage || !strings.Contains(errb, "format") {
		t.Errorf("formato inválido: %d %q", code, errb)
	}
	if code, _, _ := run(t, "audit", dir); code != ExitFindings {
		t.Errorf("audit con un crítico: %d", code)
	}
	if code, out, _ := run(t, "audit", dir, "--only", "low"); code != 0 || strings.Contains(out, "event-stream@") {
		t.Errorf("audit --only low no debe mostrar ni fallar por el crítico: %d\n%s", code, out)
	}
}

func TestScanJSONAndOutputFile(t *testing.T) {
	dir := setup(t)
	code, out, _ := run(t, "scan", dir, "--format", "json")
	if code != 0 {
		t.Fatal(code)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("JSON inválido: %v\n%s", err, out)
	}
	if rep["tool"] != "depsentinel" || rep["offline"] != true {
		t.Errorf("informe: %v", rep)
	}
	file := filepath.Join(t.TempDir(), "report.json")
	if code, out, _ := run(t, "scan", dir, "--format", "json", "--output", file); code != 0 || out != "" {
		t.Errorf("--output: %d %q", code, out)
	}
	if b, err := os.ReadFile(file); err != nil || !json.Valid(b) {
		t.Errorf("fichero de salida: %v", err)
	}
	code, out, _ = run(t, "scan", dir, "--format", "markdown")
	if code != 0 || !strings.Contains(out, "<!-- depsentinel-report -->") {
		t.Errorf("markdown: %s", out)
	}
	code, out, _ = run(t, "scan", dir, "--format", "github")
	if code != 0 || !strings.Contains(out, "::error ") {
		t.Errorf("github: %s", out)
	}
}

func TestAllowlistFlow(t *testing.T) {
	dir := setup(t)
	if code, _, errb := run(t, "allowlist", "add", "lodash", "--dir", dir); code != ExitUsage || !strings.Contains(errb, "justification") {
		t.Errorf("sin motivo: %d %q", code, errb)
	}
	if code, out, _ := run(t, "allowlist", "add", "event-stream", "--reason", "genérica", "--dir", dir); code != 0 || !strings.Contains(out, "Añadido") {
		t.Errorf("add: %d %q", code, out)
	}
	if code, _, _ := run(t, "scan", dir, "--ci"); code != ExitFindings {
		t.Error("una excepción genérica no puede ocultar un paquete malicioso")
	}
	if code, _, errb := run(t, "allowlist", "add", "event-stream", "--rule", "malicious", "--reason", "x", "--dir", dir); code != ExitUsage || !strings.Contains(errb, "versión") {
		t.Errorf("malware sin versión: %d %q", code, errb)
	}
	if code, _, _ := run(t, "allowlist", "add", "event-stream@3.3.6", "--rule", "malicious", "--reason", "falso positivo confirmado", "--dir", dir); code != 0 {
		t.Fatal("add malicious con versión")
	}
	if code, out, _ := run(t, "scan", dir, "--ci"); code != 0 || !strings.Contains(out, "allowlisted") {
		t.Errorf("con excepción explícita el build pasa: %d\n%s", code, out)
	}
	if code, out, _ := run(t, "allowlist", "list", "--dir", dir); code != 0 || !strings.Contains(out, "falso positivo confirmado") || !strings.Contains(out, "event-stream") {
		t.Errorf("list: %d %q", code, out)
	}
	if code, out, _ := run(t, "scan", dir, "--show-allowed"); code != 0 || !strings.Contains(out, "event-stream@3.3.6") {
		t.Errorf("--show-allowed: %d", code)
	}
	if code, _, _ := run(t, "allowlist", "remove", "event-stream", "--dir", dir); code != 0 {
		t.Error("remove")
	}
	if code, _, errb := run(t, "allowlist", "remove", "no-esta", "--dir", dir); code != ExitUsage {
		t.Errorf("remove inexistente: %d %q", code, errb)
	}
	if code, _, _ := run(t, "allowlist", "add", "x", "--rule", "regla-inventada", "--reason", "r", "--dir", dir); code != ExitUsage {
		t.Error("unknown rule")
	}
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DEPSENTINEL_CACHE_DIR", t.TempDir())
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
	code, out, _ := run(t, "init", dir, "--workflow")
	if code != 0 || !strings.Contains(out, "go.mod") {
		t.Fatalf("init: %d %q", code, out)
	}
	for _, f := range []string{".depsentinel.json", ".depsentinel/allowlist.json", ".github/workflows/depsentinel.yml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("falta %s", f)
		}
	}
	if _, out, _ := run(t, "init", dir); !strings.Contains(out, "Already exists") {
		t.Errorf("segunda ejecución: %q", out)
	}
	// la configuración generada es válida y se usa
	if code, _, _ := run(t, "scan", dir, "--offline", "--quiet"); code != 0 {
		t.Errorf("scan con la configuración generada: %d", code)
	}
	_ = os.WriteFile(filepath.Join(dir, ".depsentinel.json"), []byte(`{"fail_on":"critical","disabled_rules":["no-existe"]}`), 0o644)
	if code, _, errb := run(t, "scan", dir, "--offline"); code != ExitUsage || !strings.Contains(errb, "unknown rule") {
		t.Errorf("configuración inválida: %d %q", code, errb)
	}
}

func TestSBOMAndReport(t *testing.T) {
	dir := setup(t)
	sbom := filepath.Join(t.TempDir(), "sbom.json")
	if code, _, errb := run(t, "sbom", dir, "--format", "cyclonedx", "--output", sbom); code != 0 {
		t.Fatalf("sbom: %d %q", code, errb)
	}
	var doc map[string]any
	b, _ := os.ReadFile(sbom)
	if err := json.Unmarshal(b, &doc); err != nil || doc["bomFormat"] != "CycloneDX" || len(doc["components"].([]any)) != 2 {
		t.Errorf("sbom: %v %v", err, doc)
	}
	if code, _, _ := run(t, "sbom", dir, "--format", "spdx"); code != ExitUsage {
		t.Error("formato SBOM no soportado")
	}
	jsonReport := filepath.Join(t.TempDir(), "r.json")
	run(t, "scan", dir, "--format", "json", "-o", jsonReport)
	html := filepath.Join(t.TempDir(), "r.html")
	if code, out, _ := run(t, "report", "--html", "--input", jsonReport, "-o", html); code != 0 || !strings.Contains(out, "Informe escrito") {
		t.Fatalf("report --input: %d %q", code, out)
	}
	if b, _ := os.ReadFile(html); !strings.Contains(string(b), `"tool":"depsentinel"`) {
		t.Error("el HTML debe contener el informe")
	}
	html2 := filepath.Join(t.TempDir(), "r2.html")
	if code, _, _ := run(t, "report", dir, "-o", html2); code != 0 {
		t.Error("report escaneando")
	}
	if _, err := os.Stat(html2); err != nil {
		t.Error("report debe crear el fichero")
	}
	if code, _, _ := run(t, "report", "--input", filepath.Join(dir, "package.json"), "-o", html); code == 0 {
		t.Error("un JSON que no es un informe debe fallar")
	}
}

func TestDBCommands(t *testing.T) {
	setup(t)
	if code, out, _ := run(t, "db", "status"); code != 0 || !strings.Contains(out, "Semilla embebida") || !strings.Contains(out, "ninguno") {
		t.Errorf("status: %d %q", code, out)
	}
	if code, _, _ := run(t, "db", "clean", "--all"); code != 0 {
		t.Error("clean")
	}
	t.Setenv("DEPSENTINEL_OFFLINE", "")
	if code, _, errb := run(t, "db", "update", "--feed-url", "http://example.com/db"); code != ExitIncomplete || !strings.Contains(errb, "https") {
		t.Errorf("update con http remoto: %d %q", code, errb)
	}
}

func TestFixEndToEnd(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name string } `json:"package"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			var out struct {
				Results []map[string]any `json:"results"`
			}
			for _, q := range req.Queries {
				res := map[string]any{}
				if q.Package.Name == "lodash" {
					res["vulns"] = []map[string]string{{"id": "GHSA-lodash", "modified": "2024-01-01T00:00:00Z"}}
				}
				out.Results = append(out.Results, res)
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.URL.Path == "/v1/vulns/GHSA-lodash":
			_, _ = w.Write([]byte(`{"id":"GHSA-lodash","summary":"Prototype pollution","modified":"2024-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},
			 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer osv.Close()
	dir := setup(t)
	t.Setenv("DEPSENTINEL_OFFLINE", "")
	t.Setenv("DEPSENTINEL_OSV_URL", osv.URL)
	t.Setenv("DEPSENTINEL_NPM_URL", osv.URL) // el "registry" responde 404 a todo: se ignora
	pj := filepath.Join(dir, "package.json")
	before, _ := os.ReadFile(pj)

	code, out, _ := run(t, "fix", dir, "--dry-run", "--no-registry-ignored-flag")
	if code != ExitUsage {
		t.Errorf("flag inexistente: %d", code)
	}
	code, out, errb := run(t, "fix", dir, "--dry-run")
	if code != 0 || !strings.Contains(out, `lodash: "4.17.15" → "4.17.21"`) || !strings.Contains(out, "--dry-run") {
		t.Fatalf("dry-run: %d\n%s\n%s", code, out, errb)
	}
	if after, _ := os.ReadFile(pj); !bytes.Equal(before, after) {
		t.Error("--dry-run no debe modificar nada")
	}
	code, out, _ = run(t, "fix", dir)
	if code != 0 || !strings.Contains(out, "Ficheros modificados: package.json") || !strings.Contains(out, "npm install") {
		t.Fatalf("fix: %d\n%s", code, out)
	}
	after, _ := os.ReadFile(pj)
	if !strings.Contains(string(after), `"lodash":"4.17.21"`) && !strings.Contains(string(after), `"lodash": "4.17.21"`) {
		t.Errorf("package.json: %s", after)
	}
}
