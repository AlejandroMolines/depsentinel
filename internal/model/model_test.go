package model

import (
	"encoding/json"
	"testing"
)

func TestSeverityParsingAndJSON(t *testing.T) {
	for in, want := range map[string]Severity{"": SeverityNone, "none": SeverityNone, "Low": SeverityLow, "medio": SeverityMedium, "ALTO": SeverityHigh, "crítico": SeverityCritical, "critical": SeverityCritical} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("grave"); err == nil {
		t.Error("una severidad desconocida debe fallar")
	}
	b, _ := json.Marshal(struct{ S Severity }{SeverityHigh})
	if string(b) != `{"S":"high"}` {
		t.Errorf("JSON: %s", b)
	}
	var back struct{ S Severity }
	if err := json.Unmarshal(b, &back); err != nil || back.S != SeverityHigh {
		t.Errorf("round trip: %v %v", back, err)
	}
	list, err := ParseSeverityList("high, critical")
	if err != nil || len(list) != 2 {
		t.Errorf("lista: %v %v", list, err)
	}
}

func TestRiskScoreAndRecommendation(t *testing.T) {
	f := func(s Severity, rule, fixed string) Finding { return Finding{Severity: s, Rule: rule, FixedIn: fixed} }
	if RiskScore(nil) != 0 {
		t.Error("sin hallazgos, riesgo 0")
	}
	crit := RiskScore([]Finding{f(SeverityCritical, "x", "")})
	high := RiskScore([]Finding{f(SeverityHigh, "x", "")})
	manyLow := RiskScore([]Finding{f(SeverityLow, "x", ""), f(SeverityLow, "x", ""), f(SeverityLow, "x", "")})
	if !(crit > high && high > manyLow) {
		t.Errorf("orden de riesgo: crit=%d high=%d lows=%d", crit, high, manyLow)
	}
	if RiskScore([]Finding{f(SeverityCritical, "x", ""), f(SeverityCritical, "x", ""), f(SeverityCritical, "x", "")}) != 100 {
		t.Error("el score se limita a 100")
	}
	cases := []struct {
		fs   []Finding
		want string
	}{
		{nil, "use"},
		{[]Finding{f(SeverityLow, "x", "")}, "use"},
		{[]Finding{f(SeverityMedium, "x", "")}, "review"},
		{[]Finding{f(SeverityHigh, "vulnerability", "1.2.3")}, "update"},
		{[]Finding{f(SeverityCritical, "malicious", "")}, "avoid"},
		{[]Finding{f(SeverityCritical, "vulnerability", "")}, "avoid"},
	}
	for _, c := range cases {
		if got := Recommendation(c.fs); got != c.want {
			t.Errorf("Recommendation(%v) = %s, quiero %s", c.fs, got, c.want)
		}
	}
}

func TestNormalizeNameAndEcosystems(t *testing.T) {
	if NormalizeName(PyPI, "Flask_SQLAlchemy.Extra") != "flask-sqlalchemy-extra" {
		t.Error("PEP 503")
	}
	if NormalizeName(Docker, "docker.io/library/Nginx") != "nginx" {
		t.Error("docker")
	}
	for in, want := range map[string]Ecosystem{"python": PyPI, "golang": Go, "gha": Actions, "NPM": NPM, "oci": Docker} {
		if got, ok := ParseEcosystem(in); !ok || got != want {
			t.Errorf("ParseEcosystem(%q) = %v %v", in, got, ok)
		}
	}
	if _, ok := ParseEcosystem("cobol"); ok {
		t.Error("ecosistema desconocido")
	}
	if PyPI.OSV() != "PyPI" || Actions.OSV() != "GitHub Actions" || Docker.OSV() != "" {
		t.Error("nombres OSV")
	}
}

func TestBuildSummaryOrdersAndCounts(t *testing.T) {
	r := &Report{Findings: []Finding{
		{Severity: SeverityLow, Ecosystem: NPM, Package: "b", Version: "1"},
		{Severity: SeverityCritical, Ecosystem: NPM, Package: "a", Version: "1", Rule: "malicious"},
	}}
	pkgs := []*Package{{Ecosystem: NPM, Name: "a", Version: "1"}, {Ecosystem: NPM, Name: "b", Version: "1"}, {Ecosystem: NPM, Name: "c", Version: "1"}}
	r.BuildSummary(pkgs)
	if r.Findings[0].Package != "a" || r.Summary.RiskLevel != "critical" || r.Summary.BySeverity["low"] != 1 || r.Summary.Packages != 3 {
		t.Errorf("resumen: %+v", r.Summary)
	}
	if r.Packages[0].Name != "a" || r.Packages[0].Recommendation != "avoid" || r.Packages[2].RiskScore != 0 {
		t.Errorf("paquetes: %+v", r.Packages)
	}
}
