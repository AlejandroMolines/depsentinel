package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/term"
)

func sample() (*model.Report, []*model.Package) {
	pkgs := []*model.Package{
		{Ecosystem: model.NPM, Name: "lodash", Version: "4.17.15", Direct: true, Source: "package-lock.json"},
		{Ecosystem: model.NPM, Name: "@babel/core", Version: "7.22.5", Direct: true, Dev: true, Integrity: "sha512-" + strings.Repeat("A", 86) + "==", Resolved: "https://registry.npmjs.org/@babel/core/-/core-7.22.5.tgz"},
		{Ecosystem: model.NPM, Name: "event-stream", Version: "3.3.6"},
	}
	rep := &model.Report{Tool: "depsentinel", Version: "0.1.0", SchemaVersion: 1, GeneratedAt: time.Now(), Target: "/proyecto",
		Ecosystems: []model.Ecosystem{model.NPM}, Sources: []string{"package-lock.json"}}
	rep.Findings = []model.Finding{
		{ID: "GHSA-1", Rule: "vulnerability", Severity: model.SeverityHigh, Ecosystem: model.NPM, Package: "lodash", Version: "4.17.15", Title: "Prototype | Pollution", FixedIn: "4.17.19", Fix: "Actualiza a 4.17.19", Source: "package-lock.json"},
		{ID: "DS-0001", Rule: "malicious", Severity: model.SeverityCritical, Ecosystem: model.NPM, Package: "event-stream", Version: "3.3.6", Title: "Versión comprometida", Fix: "Elimínalo"},
		{ID: "DS-X", Rule: "unmaintained", Severity: model.SeverityLow, Ecosystem: model.NPM, Package: "lodash", Version: "4.17.15", Title: "Sin mantenimiento"},
		{ID: "DS-XSS", Rule: "typosquat", Severity: model.SeverityMedium, Ecosystem: model.NPM, Package: "x", Title: `</script><img src=x onerror=alert(1)>`},
	}
	rep.BuildSummary(pkgs)
	return rep, pkgs
}

func TestTable(t *testing.T) {
	rep, _ := sample()
	var b bytes.Buffer
	Table(&b, rep, TableOptions{Color: term.Palette{}, FailOn: model.SeverityHigh, Width: 100})
	out := b.String()
	for _, want := range []string{"SEVERITY", "critical", "event-stream@3.3.6", "lodash@4.17.15", "fixed in 4.17.19", "What to do first", "1 critical", "1 high", "1 medium", "1 low", "Overall risk: CRITICAL", "build fails"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("sin paleta no debe haber códigos ANSI")
	}
	// el primero es el crítico
	if strings.Index(out, "event-stream") > strings.Index(out, "lodash") {
		t.Error("orden por severidad")
	}
	b.Reset()
	Table(&b, rep, TableOptions{Only: []model.Severity{model.SeverityCritical}})
	if strings.Contains(b.String(), "lodash@") {
		t.Error("--only critical no debe mostrar lodash")
	}
	b.Reset()
	Table(&b, &model.Report{Version: "x", Summary: model.Summary{BySeverity: map[string]int{}}}, TableOptions{})
	if !strings.Contains(b.String(), "No supported manifests found") {
		t.Error("sin manifiestos debe explicarlo")
	}
	b.Reset()
	Table(&b, rep, TableOptions{Color: term.Palette{Enabled: true}})
	if !strings.Contains(b.String(), "\x1b[1;31m") {
		t.Error("con color, lo crítico va en rojo y negrita")
	}
}

func TestMarkdown(t *testing.T) {
	rep, _ := sample()
	md := Markdown(rep, MarkdownOptions{FailOn: model.SeverityHigh, ReportURL: "https://example.com/r"})
	for _, want := range []string{CommentMarker, "risk **critical**", "2 high or critical dependency finding(s)", "| 🔴 critical |", "Prototype \\| Pollution", "How to fix", "allowlist add", "[Full report](https://example.com/r)", "The check fails"} {
		if !strings.Contains(md, want) {
			t.Errorf("falta %q en:\n%s", want, md)
		}
	}
	if strings.Contains(md, "</script><img") {
		t.Error("el Markdown debe escapar HTML de los títulos")
	}
	md = Markdown(rep, MarkdownOptions{MaxRows: 1})
	if !strings.Contains(md, "more finding(s)") {
		t.Error("el recorte de filas debe avisar")
	}
	clean := &model.Report{Summary: model.Summary{Packages: 3}, Ecosystems: []model.Ecosystem{model.NPM}}
	if md := Markdown(clean, MarkdownOptions{FailOn: model.SeverityHigh}); !strings.Contains(md, "No findings") || !strings.Contains(md, "The check passes") {
		t.Errorf("limpio: %s", md)
	}
}

func TestGitHubAnnotations(t *testing.T) {
	rep, _ := sample()
	rep.Findings[0].Title = "linea1\nlinea2: 100%"
	var b bytes.Buffer
	GitHubAnnotations(&b, rep)
	out := b.String()
	if !strings.Contains(out, "::error file=package-lock.json,title=DepSentinel vulnerability::") {
		t.Errorf("anotación de error: %s", out)
	}
	if strings.Contains(out, "linea1\nlinea2") || !strings.Contains(out, "linea1 linea2: 100%") && !strings.Contains(out, "%0A") && !strings.Contains(out, "linea1 linea2") {
		t.Errorf("escape de saltos de línea: %s", out)
	}
	if !strings.Contains(out, "::warning ") || !strings.Contains(out, "::notice ") {
		t.Errorf("niveles: %s", out)
	}
}

func TestHTMLEmbedding(t *testing.T) {
	rep, _ := sample()
	html, err := HTML(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if strings.Contains(s, dataMarker) {
		t.Error("el marcador debe sustituirse")
	}
	if !strings.Contains(s, `"tool":"depsentinel"`) {
		t.Error("el informe debe quedar incrustado")
	}
	if strings.Contains(s, "</script><img") || strings.Count(s, "</script>") != strings.Count(string(webTemplate()), "</script>") {
		t.Error("un título malicioso no puede cerrar la etiqueta <script> (XSS)")
	}
	raw, _ := json.Marshal(rep)
	if _, err := HTMLFromJSON(raw); err != nil {
		t.Errorf("HTMLFromJSON: %v", err)
	}
	if _, err := HTMLFromJSON([]byte(`{"tool":"otra-cosa"}`)); err == nil {
		t.Error("un JSON que no es de DepSentinel debe rechazarse")
	}
	if _, err := HTMLFromJSON([]byte(`no json`)); err == nil {
		t.Error("JSON inválido")
	}
}

func TestCycloneDX(t *testing.T) {
	_, pkgs := sample()
	pkgs[0].DependsOn = []string{pkgs[2].Key()}
	pkgs = append(pkgs,
		&model.Package{Ecosystem: model.Go, Name: "github.com/gin-gonic/gin", Version: "v1.8.1+incompatible", Direct: true},
		&model.Package{Ecosystem: model.PyPI, Name: "flask-sqlalchemy", Version: "2.5.1"},
		&model.Package{Ecosystem: model.Docker, Name: "nginx", Version: "1.25", Integrity: "sha256:" + strings.Repeat("ab", 32), Direct: true},
		&model.Package{Ecosystem: model.Actions, Name: "actions/checkout", Version: "v4", Direct: true})
	data, err := CycloneDX(pkgs, SBOMOptions{RootName: "demo", RootVersion: "1.0.0", Now: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), ToolVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.5" || !strings.HasPrefix(doc["serialNumber"].(string), "urn:uuid:") {
		t.Errorf("cabecera: %v", doc)
	}
	comps := doc["components"].([]any)
	if len(comps) != 7 {
		t.Fatalf("componentes: %d", len(comps))
	}
	purls := map[string]map[string]any{}
	for _, c := range comps {
		m := c.(map[string]any)
		purls[m["purl"].(string)] = m
	}
	for _, p := range []string{"pkg:npm/%40babel/core@7.22.5", "pkg:npm/lodash@4.17.15", "pkg:golang/github.com/gin-gonic/gin@v1.8.1%2Bincompatible",
		"pkg:pypi/flask-sqlalchemy@2.5.1", "pkg:docker/nginx@1.25", "pkg:githubactions/actions/checkout@v4"} {
		if purls[p] == nil {
			t.Errorf("falta el purl %s (hay %v)", p, keys(purls))
		}
	}
	babel := purls["pkg:npm/%40babel/core@7.22.5"]
	if babel["group"] != "@babel" || babel["name"] != "core" || babel["scope"] != "optional" {
		t.Errorf("npm con scope: %v", babel)
	}
	if h := babel["hashes"].([]any)[0].(map[string]any); h["alg"] != "SHA-512" || h["content"] != strings.Repeat("0", 128) {
		t.Errorf("hash de integridad: %v", h)
	}
	if purls["pkg:npm/lodash@4.17.15"]["hashes"] != nil {
		t.Error("un componente sin integridad no debe llevar hashes")
	}
	if got := hashesFrom("sha512-AAAA sha1-" + strings.Repeat("A", 27) + "="); len(got) != 1 || got[0].Alg != "SHA-1" {
		t.Errorf("hashes con longitud incorrecta deben omitirse: %v", got)
	}
	if nginx := purls["pkg:docker/nginx@1.25"]; nginx["type"] != "container" || nginx["hashes"] == nil {
		t.Errorf("docker: %v", nginx)
	}
	deps := doc["dependencies"].([]any)
	root := deps[0].(map[string]any)
	if root["ref"] != "depsentinel:root" || len(root["dependsOn"].([]any)) != 5 {
		t.Errorf("la raíz depende de los directos: %v", root)
	}
	foundEdge := false
	for _, d := range deps {
		m := d.(map[string]any)
		if m["ref"] == "pkg:npm/lodash@4.17.15" && len(m["dependsOn"].([]any)) == 1 {
			foundEdge = true
		}
	}
	if !foundEdge {
		t.Error("el grafo de dependencias debe conservar las aristas")
	}
}

func keys(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
