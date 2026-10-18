// Package osv es un cliente de la API de OSV.dev (https://osv.dev).
package osv

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/workpool"
)

// DefaultBaseURL es la API pública de OSV.
const DefaultBaseURL = "https://api.osv.dev"

const batchSize = 500

// Client consulta OSV. Cache puede ser nil.
type Client struct {
	HTTP    *httpx.Client
	Base    string
	Cache   *cache.Cache
	Workers int
}

// New crea un cliente de OSV.
func New(h *httpx.Client, base string, c *cache.Cache) *Client {
	if base == "" {
		base = DefaultBaseURL
	}
	return &Client{HTTP: h, Base: strings.TrimRight(base, "/"), Cache: c, Workers: 8}
}

// Query identifica un paquete+versión en el vocabulario de OSV.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

// VulnRef es la referencia corta que devuelve querybatch.
type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type pkgRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchQuery struct {
	Package   pkgRef `json:"package"`
	Version   string `json:"version,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

type batchResult struct {
	Vulns         []VulnRef `json:"vulns"`
	NextPageToken string    `json:"next_page_token"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

// QueryBatch consulta muchos paquetes a la vez y devuelve las referencias por posición.
func (c *Client) QueryBatch(ctx context.Context, qs []Query) ([][]VulnRef, error) {
	out := make([][]VulnRef, len(qs))
	type item struct {
		idx   int
		token string
	}
	pending := make([]item, len(qs))
	for i := range qs {
		pending[i] = item{idx: i}
	}
	for round := 0; len(pending) > 0 && round < 20; round++ {
		var next []item
		for start := 0; start < len(pending); start += batchSize {
			end := min(start+batchSize, len(pending))
			chunk := pending[start:end]
			req := struct {
				Queries []batchQuery `json:"queries"`
			}{}
			for _, it := range chunk {
				q := qs[it.idx]
				req.Queries = append(req.Queries, batchQuery{
					Package:   pkgRef{Name: q.Name, Ecosystem: q.Ecosystem},
					Version:   q.Version,
					PageToken: it.token,
				})
			}
			var resp batchResponse
			if err := c.HTTP.PostJSON(ctx, c.Base+"/v1/querybatch", req, &resp); err != nil {
				return nil, err
			}
			if len(resp.Results) != len(chunk) {
				return nil, fmt.Errorf("OSV devolvió %d resultados para %d consultas", len(resp.Results), len(chunk))
			}
			for k, r := range resp.Results {
				out[chunk[k].idx] = append(out[chunk[k].idx], r.Vulns...)
				if r.NextPageToken != "" {
					next = append(next, item{idx: chunk[k].idx, token: r.NextPageToken})
				}
			}
		}
		pending = next
	}
	return out, nil
}

// Vuln es un subconjunto del esquema OSV.
type Vuln struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Aliases          []string        `json:"aliases"`
	Modified         string          `json:"modified"`
	Published        string          `json:"published"`
	Withdrawn        string          `json:"withdrawn"`
	Severities       []SeverityEntry `json:"severity"`
	Affected         []Affected      `json:"affected"`
	References       []Reference     `json:"references"`
	DatabaseSpecific map[string]any  `json:"database_specific"`
}

// SeverityEntry es una puntuación (por ejemplo un vector CVSS).
type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Reference es un enlace asociado a la vulnerabilidad.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected describe qué paquete y qué rangos afecta.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}

// GetVuln descarga el detalle de una vulnerabilidad (con caché por id+modified).
func (c *Client) GetVuln(ctx context.Context, ref VulnRef) (*Vuln, error) {
	var v Vuln
	if c.Cache.GetJSON("osv", ref.ID, 0, &v) && v.ID != "" && (ref.Modified == "" || v.Modified == ref.Modified) {
		return &v, nil
	}
	v = Vuln{}
	if err := c.HTTP.GetJSON(ctx, c.Base+"/v1/vulns/"+url.PathEscape(ref.ID), nil, &v); err != nil {
		return nil, err
	}
	if v.ID == "" {
		v.ID = ref.ID
	}
	_ = c.Cache.PutJSON("osv", ref.ID, &v)
	return &v, nil
}

// FetchVulns descarga en paralelo los detalles de varias vulnerabilidades.
// Devuelve lo que se pudo obtener y el número de fallos.
func (c *Client) FetchVulns(ctx context.Context, refs []VulnRef) (map[string]*Vuln, int, error) {
	uniq := map[string]VulnRef{}
	for _, r := range refs {
		if _, ok := uniq[r.ID]; !ok {
			uniq[r.ID] = r
		}
	}
	list := make([]VulnRef, 0, len(uniq))
	for _, r := range uniq {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	out := make(map[string]*Vuln, len(list))
	var mu sync.Mutex
	failed := 0
	var firstErr error
	workpool.ForEach(ctx, c.Workers, len(list), func(ctx context.Context, i int) {
		v, err := c.GetVuln(ctx, list[i])
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		out[list[i].ID] = v
	})
	return out, failed, firstErr
}

var malwareSummary = regexp.MustCompile(`(?i)^(malicious code|malware)\b.*\bin\b`)

// IsMalicious indica si el aviso describe código malicioso (IDs MAL-* de OpenSSF o avisos "Malware in ...").
func (v *Vuln) IsMalicious() bool {
	if strings.HasPrefix(v.ID, "MAL-") {
		return true
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "MAL-") {
			return true
		}
	}
	return malwareSummary.MatchString(strings.TrimSpace(v.Summary))
}

// Severity estima la severidad: etiqueta de GitHub, si no CVSS v3, si no "medium".
func (v *Vuln) Severity() model.Severity {
	if v.IsMalicious() {
		return model.SeverityCritical
	}
	if s, ok := v.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "CRITICAL":
			return model.SeverityCritical
		case "HIGH":
			return model.SeverityHigh
		case "MODERATE", "MEDIUM":
			return model.SeverityMedium
		case "LOW":
			return model.SeverityLow
		}
	}
	for _, sv := range v.Severities {
		if score, ok := CVSS3(sv.Score); ok {
			return FromScore(score)
		}
	}
	return model.SeverityMedium
}

// FromScore traduce una puntuación CVSS a severidad.
func FromScore(score float64) model.Severity {
	switch {
	case score >= 9.0:
		return model.SeverityCritical
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	}
	return model.SeverityLow
}

// Title devuelve un título corto.
func (v *Vuln) Title() string {
	t := strings.TrimSpace(v.Summary)
	if t == "" {
		t = strings.TrimSpace(v.Details)
		if i := strings.IndexAny(t, ".\n"); i > 0 {
			t = t[:i]
		}
	}
	t = strings.Join(strings.Fields(t), " ")
	if len(t) > 160 {
		t = t[:157] + "..."
	}
	if t == "" {
		t = "Vulnerabilidad sin descripción"
	}
	return t
}

// CVEs devuelve los alias que son identificadores CVE.
func (v *Vuln) CVEs() []string {
	var out []string
	for _, a := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

// URL devuelve el enlace canónico al aviso en osv.dev.
func (v *Vuln) URL() string { return "https://osv.dev/vulnerability/" + url.PathEscape(v.ID) }

// ExtraReferences devuelve hasta max enlaces útiles (avisos y artículos).
func (v *Vuln) ExtraReferences(max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, want := range []string{"ADVISORY", "ARTICLE", "WEB", "FIX", "REPORT"} {
		for _, r := range v.References {
			if r.Type == want && r.URL != "" && !seen[r.URL] && strings.HasPrefix(r.URL, "http") {
				seen[r.URL] = true
				out = append(out, r.URL)
				if len(out) >= max {
					return out
				}
			}
		}
	}
	return out
}

func sameName(osvEco, a, b string) bool {
	if osvEco == "PyPI" {
		return model.NormalizeName(model.PyPI, a) == model.NormalizeName(model.PyPI, b)
	}
	return a == b
}

// FixedVersion devuelve la menor versión corregida posterior a la instalada ("" si no hay).
func (v *Vuln) FixedVersion(osvEco, name, installed string, cmp func(a, b string) int) string {
	best := ""
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, osvEco) || !sameName(osvEco, a.Package.Name, name) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, ev := range r.Events {
				fixed := ev["fixed"]
				if fixed == "" {
					continue
				}
				if cmp(fixed, installed) > 0 && (best == "" || cmp(fixed, best) < 0) {
					best = fixed
				}
			}
		}
	}
	return best
}

func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return 0
	case strings.HasPrefix(id, "CVE-"):
		return 1
	case strings.HasPrefix(id, "PYSEC-"), strings.HasPrefix(id, "GO-"):
		return 2
	case strings.HasPrefix(id, "MAL-"):
		return 3
	}
	return 4
}

// GroupAliases fusiona avisos que son el mismo problema (comparten ID o alias).
// Devuelve un aviso representativo por grupo con los demás identificadores en Aliases.
func GroupAliases(vs []*Vuln) []*Vuln {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] == "" || parent[x] == x {
			parent[x] = x
			return x
		}
		r := find(parent[x])
		parent[x] = r
		return r
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	for _, v := range vs {
		find(v.ID)
		for _, a := range v.Aliases {
			union(v.ID, a)
		}
	}
	groups := map[string][]*Vuln{}
	for _, v := range vs {
		r := find(v.ID)
		groups[r] = append(groups[r], v)
	}
	var out []*Vuln
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool {
			if ri, rj := idRank(g[i].ID), idRank(g[j].ID); ri != rj {
				return ri < rj
			}
			return g[i].ID < g[j].ID
		})
		rep := *g[0]
		set := map[string]bool{}
		var aliases []string
		add := func(id string) {
			if id != "" && id != rep.ID && !set[id] {
				set[id] = true
				aliases = append(aliases, id)
			}
		}
		for _, v := range g {
			add(v.ID)
			for _, a := range v.Aliases {
				add(a)
			}
			if rep.Summary == "" {
				rep.Summary = v.Summary
			}
			if len(rep.Affected) == 0 {
				rep.Affected = v.Affected
			}
		}
		sort.Strings(aliases)
		rep.Aliases = aliases
		out = append(out, &rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
