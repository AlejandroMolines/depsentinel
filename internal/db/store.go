// Package db gestiona la base de datos local: semilla embebida + feed descargado con `db update`.
package db

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	dbdata "github.com/AlejandroMolines/depsentinel/db"
	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// MaliciousEntry es un paquete (o versiones) conocido como malicioso o comprometido.
type MaliciousEntry struct {
	ID        string          `json:"id"`
	Ecosystem model.Ecosystem `json:"ecosystem"`
	Name      string          `json:"name"`
	Versions  []string        `json:"versions"` // vacío o ["*"] = todas
	Kind      string          `json:"kind"`     // malware | compromised | sabotage | protestware
	Summary   string          `json:"summary"`
	Reference string          `json:"reference"`
}

type maliciousFile struct {
	Schema  int              `json:"schema"`
	Updated string           `json:"updated"`
	Entries []MaliciousEntry `json:"entries"`
}

type popularFile struct {
	Schema   int                 `json:"schema"`
	Updated  string              `json:"updated"`
	Packages map[string][]string `json:"packages"`
}

// BuiltinAllow es una excepción integrada.
type BuiltinAllow struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Rule      string `json:"rule"`
	Reason    string `json:"reason"`
}

type allowFile struct {
	Schema  int            `json:"schema"`
	Entries []BuiltinAllow `json:"entries"`
}

// FeedMeta describe el último feed descargado.
type FeedMeta struct {
	Version string    `json:"version"`
	Source  string    `json:"source"`
	Signed  bool      `json:"signed"`
	Checked time.Time `json:"checked"`
}

// Info resume el estado de la base de datos cargada.
type Info struct {
	SeedUpdated      string         `json:"seed_updated"`
	MaliciousEntries int            `json:"malicious_entries"`
	Popular          map[string]int `json:"popular"`
	Feed             *FeedMeta      `json:"feed,omitempty"`
}

// Store es la base de datos en memoria.
type Store struct {
	malicious map[string][]MaliciousEntry
	seen      map[string]bool
	popular   map[model.Ecosystem][]string
	popSet    map[model.Ecosystem]map[string]bool
	builtin   []BuiltinAllow
	info      Info
}

// Load carga la semilla embebida y, si existe, el feed de cacheDir/feed.
func Load(cacheDir string) (*Store, error) {
	s := &Store{
		malicious: map[string][]MaliciousEntry{},
		seen:      map[string]bool{},
		popular:   map[model.Ecosystem][]string{},
		popSet:    map[model.Ecosystem]map[string]bool{},
		info:      Info{Popular: map[string]int{}},
	}
	if err := s.addMalicious(dbdata.Malicious, true); err != nil {
		return nil, fmt.Errorf("base de datos semilla corrupta (malicious.json): %w", err)
	}
	if err := s.addPopular(dbdata.Popular); err != nil {
		return nil, fmt.Errorf("base de datos semilla corrupta (popular.json): %w", err)
	}
	var af allowFile
	if err := json.Unmarshal(dbdata.Allowlist, &af); err != nil {
		return nil, fmt.Errorf("base de datos semilla corrupta (allowlist.json): %w", err)
	}
	s.builtin = af.Entries
	if cacheDir != "" {
		feed := filepath.Join(cacheDir, "feed")
		if b, err := os.ReadFile(filepath.Join(feed, "malicious.json")); err == nil {
			_ = s.addMalicious(b, false)
		}
		if b, err := os.ReadFile(filepath.Join(feed, "popular.json")); err == nil {
			_ = s.addPopular(b)
		}
		if b, err := os.ReadFile(filepath.Join(feed, "meta.json")); err == nil {
			var m FeedMeta
			if json.Unmarshal(b, &m) == nil {
				s.info.Feed = &m
			}
		}
	}
	return s, nil
}

func (s *Store) addMalicious(data []byte, seed bool) error {
	var f maliciousFile
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	if seed {
		s.info.SeedUpdated = f.Updated
	}
	for _, e := range f.Entries {
		if e.Name == "" || e.Ecosystem == "" {
			continue
		}
		uid := string(e.Ecosystem) + "|" + e.ID + "|" + e.Name + "|" + strings.Join(e.Versions, ",")
		if s.seen[uid] {
			continue
		}
		s.seen[uid] = true
		key := string(e.Ecosystem) + ":" + model.NormalizeName(e.Ecosystem, e.Name)
		s.malicious[key] = append(s.malicious[key], e)
		s.info.MaliciousEntries++
	}
	return nil
}

func (s *Store) addPopular(data []byte) error {
	var f popularFile
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	for k, names := range f.Packages {
		eco := model.Ecosystem(k)
		if s.popSet[eco] == nil {
			s.popSet[eco] = map[string]bool{}
		}
		for _, n := range names {
			n = model.NormalizeName(eco, n)
			if n == "" || s.popSet[eco][n] {
				continue
			}
			s.popSet[eco][n] = true
			s.popular[eco] = append(s.popular[eco], n)
		}
		s.info.Popular[k] = len(s.popular[eco])
	}
	return nil
}

func (e MaliciousEntry) matches(version string) bool {
	if len(e.Versions) == 0 {
		return true
	}
	v := strings.TrimPrefix(version, "v")
	for _, ev := range e.Versions {
		if ev == "*" || strings.TrimPrefix(ev, "v") == v {
			return true
		}
	}
	return false
}

// LookupMalicious devuelve las entradas conocidas para ese paquete y versión.
func (s *Store) LookupMalicious(eco model.Ecosystem, name, version string) []MaliciousEntry {
	if s == nil {
		return nil
	}
	var out []MaliciousEntry
	for _, e := range s.malicious[string(eco)+":"+model.NormalizeName(eco, name)] {
		if e.matches(version) {
			out = append(out, e)
		}
	}
	return out
}

// IsPopular indica si el nombre está en la lista de populares del ecosistema.
func (s *Store) IsPopular(eco model.Ecosystem, name string) bool {
	if s == nil {
		return false
	}
	return s.popSet[eco][model.NormalizeName(eco, name)]
}

// Popular devuelve los nombres populares (normalizados) del ecosistema.
func (s *Store) Popular(eco model.Ecosystem) []string {
	if s == nil {
		return nil
	}
	return s.popular[eco]
}

// IsBenign indica si hay una excepción integrada para ese paquete y regla.
func (s *Store) IsBenign(eco model.Ecosystem, name, rule string) bool {
	if s == nil {
		return false
	}
	n := strings.ToLower(name)
	for _, b := range s.builtin {
		if b.Ecosystem != string(eco) || b.Rule != rule {
			continue
		}
		if ok, _ := path.Match(strings.ToLower(b.Name), n); ok {
			return true
		}
	}
	return false
}

// Info devuelve un resumen del estado de la base de datos.
func (s *Store) Info() Info { return s.info }
