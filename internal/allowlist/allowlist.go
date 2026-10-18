// Package allowlist gestiona la lista blanca con justificación (.depsentinel/allowlist.json).
package allowlist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// Entry es una excepción con su justificación.
type Entry struct {
	Ecosystem string `json:"ecosystem"`         // "*" o un ecosistema
	Name      string `json:"name"`              // nombre exacto o patrón (p. ej. @babel/*)
	Version   string `json:"version,omitempty"` // vacío o "*" = todas
	Rule      string `json:"rule,omitempty"`    // vacío o "*" = todas (salvo malicious)
	Reason    string `json:"reason"`
	Added     string `json:"added,omitempty"`
	Expires   string `json:"expires,omitempty"` // AAAA-MM-DD
}

type file struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// List es la lista blanca cargada desde disco.
type List struct {
	Path    string
	Entries []Entry
}

// Load lee la lista; si el fichero no existe devuelve una lista vacía.
func Load(p string) (*List, error) {
	l := &List{Path: p}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return l, nil
		}
		return nil, err
	}
	var f file
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	l.Entries = f.Entries
	for i, e := range l.Entries {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%s: entrada %d: %w", p, i+1, err)
		}
	}
	return l, nil
}

// Save escribe la lista (crea el directorio si hace falta).
func (l *List) Save() error {
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(file{Version: 1, Entries: l.Entries}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(l.Path, append(b, '\n'), 0o644)
}

// Validate comprueba que la entrada es utilizable y tiene justificación.
func (e Entry) Validate() error {
	if strings.TrimSpace(e.Name) == "" {
		return errors.New("falta el nombre del paquete")
	}
	if strings.TrimSpace(e.Reason) == "" {
		return errors.New("missing justification (reason): every exception must explain why it is safe")
	}
	if e.Ecosystem != "" && e.Ecosystem != "*" {
		if _, ok := model.ParseEcosystem(e.Ecosystem); !ok {
			return fmt.Errorf("unknown ecosystem %q", e.Ecosystem)
		}
	}
	if e.Expires != "" {
		if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
			return fmt.Errorf("fecha de caducidad inválida %q (usa AAAA-MM-DD)", e.Expires)
		}
	}
	if e.Rule == "malicious" && (e.Version == "" || e.Version == "*") {
		return errors.New("para permitir un paquete malicioso conocido hay que fijar la versión exacta (--version)")
	}
	return nil
}

// Expired indica si la entrada ya caducó.
func (e Entry) Expired(now time.Time) bool {
	if e.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", e.Expires)
	if err != nil {
		return false
	}
	return now.After(t.Add(24 * time.Hour))
}

func sameEntry(a, b Entry) bool {
	return strings.EqualFold(a.Ecosystem, b.Ecosystem) && a.Name == b.Name && a.Version == b.Version && a.Rule == b.Rule
}

// Add añade o reemplaza una entrada (misma clave ecosistema+nombre+versión+regla).
func (l *List) Add(e Entry) error {
	if e.Ecosystem == "" {
		e.Ecosystem = "*"
	}
	if err := e.Validate(); err != nil {
		return err
	}
	for i := range l.Entries {
		if sameEntry(l.Entries[i], e) {
			l.Entries[i] = e
			return nil
		}
	}
	l.Entries = append(l.Entries, e)
	return nil
}

// Remove elimina las entradas de ese nombre (y opcionalmente ecosistema/versión/regla). Devuelve cuántas.
func (l *List) Remove(name, eco, version, rule string) int {
	var keep []Entry
	removed := 0
	for _, e := range l.Entries {
		match := e.Name == name &&
			(eco == "" || strings.EqualFold(e.Ecosystem, eco)) &&
			(version == "" || e.Version == version) &&
			(rule == "" || e.Rule == rule)
		if match {
			removed++
			continue
		}
		keep = append(keep, e)
	}
	l.Entries = keep
	return removed
}

func matchName(pattern, name string) bool {
	if pattern == name {
		return true
	}
	ok, _ := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	return ok
}

// Match devuelve la entrada que permite el hallazgo (si la hay y no ha caducado).
func (l *List) Match(f model.Finding, now time.Time) (*Entry, bool) {
	if l == nil {
		return nil, false
	}
	for i := range l.Entries {
		e := l.Entries[i]
		if e.Expired(now) {
			continue
		}
		if e.Ecosystem != "" && e.Ecosystem != "*" && !strings.EqualFold(e.Ecosystem, string(f.Ecosystem)) {
			continue
		}
		if !matchName(model.NormalizeName(f.Ecosystem, e.Name), model.NormalizeName(f.Ecosystem, f.Package)) {
			continue
		}
		if e.Version != "" && e.Version != "*" && strings.TrimPrefix(e.Version, "v") != strings.TrimPrefix(f.Version, "v") {
			continue
		}
		if e.Rule != "" && e.Rule != "*" && !strings.EqualFold(e.Rule, f.Rule) && !strings.EqualFold(e.Rule, f.ID) {
			continue
		}
		// Un paquete malicioso solo se permite con una excepción explícita para esa regla.
		if f.Rule == "malicious" && e.Rule != "malicious" {
			continue
		}
		return &e, true
	}
	return nil, false
}

// ExpiredEntries devuelve las entradas caducadas (para avisar al usuario).
func (l *List) ExpiredEntries(now time.Time) []Entry {
	var out []Entry
	if l == nil {
		return out
	}
	for _, e := range l.Entries {
		if e.Expired(now) {
			out = append(out, e)
		}
	}
	return out
}
