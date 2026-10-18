package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

var now = time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)

func finding(eco model.Ecosystem, name, version, rule string) model.Finding {
	return model.Finding{Ecosystem: eco, Package: name, Version: version, Rule: rule, ID: "X"}
}

func TestAddValidateAndMatch(t *testing.T) {
	l := &List{Path: filepath.Join(t.TempDir(), ".depsentinel", "allowlist.json")}
	if err := l.Add(Entry{Name: "lodash"}); err == nil || !strings.Contains(err.Error(), "justification") {
		t.Errorf("sin motivo debe fallar: %v", err)
	}
	if err := l.Add(Entry{Name: "event-stream", Rule: "malicious", Reason: "x"}); err == nil {
		t.Error("permitir malware sin versión exacta debe fallar")
	}
	if err := l.Add(Entry{Name: "lodash", Reason: "revisado manualmente"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Add(Entry{Ecosystem: "npm", Name: "@babel/*", Rule: "typosquat", Reason: "monorepo conocido"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Add(Entry{Ecosystem: "npm", Name: "legacy", Reason: "migración en curso", Expires: "2026-01-01"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Match(finding(model.NPM, "lodash", "4.17.15", "vulnerability"), now); !ok {
		t.Error("lodash con cualquier regla/versión debe permitirse")
	}
	if _, ok := l.Match(finding(model.PyPI, "lodash", "1", "typosquat"), now); !ok {
		t.Error("sin ecosistema vale para cualquiera")
	}
	if _, ok := l.Match(finding(model.NPM, "@babel/core", "7", "typosquat"), now); !ok {
		t.Error("el patrón @babel/* debe coincidir")
	}
	if _, ok := l.Match(finding(model.NPM, "@babel/core", "7", "vulnerability"), now); ok {
		t.Error("la entrada solo vale para typosquat")
	}
	if _, ok := l.Match(finding(model.NPM, "legacy", "1", "vulnerability"), now); ok {
		t.Error("una excepción caducada no debe aplicarse")
	}
	if len(l.ExpiredEntries(now)) != 1 {
		t.Error("debe avisar de la caducada")
	}
}

func TestMaliciousNeedsExplicitEntry(t *testing.T) {
	l := &List{}
	_ = l.Add(Entry{Name: "event-stream", Reason: "x"})
	f := finding(model.NPM, "event-stream", "3.3.6", "malicious")
	if _, ok := l.Match(f, now); ok {
		t.Error("una excepción genérica no puede ocultar un paquete malicioso")
	}
	if err := l.Add(Entry{Name: "event-stream", Version: "3.3.6", Rule: "malicious", Reason: "falso positivo confirmado por el equipo de seguridad"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Match(f, now); !ok {
		t.Error("con regla y versión explícitas sí debe permitirse")
	}
	if _, ok := l.Match(finding(model.NPM, "event-stream", "3.3.7", "malicious"), now); ok {
		t.Error("otra versión no queda cubierta")
	}
}

func TestSaveLoadRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "allowlist.json")
	l, err := Load(path)
	if err != nil || len(l.Entries) != 0 {
		t.Fatalf("un fichero inexistente es una lista vacía: %v %v", l, err)
	}
	_ = l.Add(Entry{Name: "a", Reason: "r", Added: "2026-10-13"})
	_ = l.Add(Entry{Name: "a", Ecosystem: "npm", Reason: "r2"})
	_ = l.Add(Entry{Name: "b", Reason: "r"})
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	l2, err := Load(path)
	if err != nil || len(l2.Entries) != 3 {
		t.Fatalf("recarga: %v %v", l2, err)
	}
	if n := l2.Remove("a", "", "", ""); n != 2 {
		t.Errorf("Remove devolvió %d", n)
	}
	if n := l2.Remove("zzz", "", "", ""); n != 0 {
		t.Error("nada que eliminar")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"entries":[{"name":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("un fichero editado a mano sin motivo debe rechazarse")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"entries":[],"extra":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("campos desconocidos deben rechazarse (detecta erratas)")
	}
}
