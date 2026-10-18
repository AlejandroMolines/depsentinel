package osv

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/semver"
)

func TestCVSS3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 4.3,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		got, ok := CVSS3(v)
		if !ok || math.Abs(got-want) > 0.001 {
			t.Errorf("CVSS3(%s) = %v (ok=%v), quiero %v", v, got, ok, want)
		}
	}
	if _, ok := CVSS3("CVSS:4.0/AV:N/AC:L"); ok {
		t.Error("CVSS v4 no está soportado y debe devolver ok=false")
	}
}

func TestSeverityMapping(t *testing.T) {
	v := &Vuln{ID: "GHSA-aaaa", DatabaseSpecific: map[string]any{"severity": "MODERATE"}}
	if v.Severity() != model.SeverityMedium {
		t.Error("MODERATE debe ser medium")
	}
	v = &Vuln{ID: "CVE-1", Severities: []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}
	if v.Severity() != model.SeverityCritical {
		t.Error("9.8 debe ser critical")
	}
	if (&Vuln{ID: "MAL-2024-1"}).Severity() != model.SeverityCritical || !(&Vuln{ID: "MAL-2024-1"}).IsMalicious() {
		t.Error("MAL-* debe ser malicioso y crítico")
	}
	if !(&Vuln{ID: "GHSA-x", Summary: "Malware in left-pad"}).IsMalicious() {
		t.Error("un aviso 'Malware in ...' debe considerarse malicioso")
	}
	if (&Vuln{ID: "GHSA-y", Summary: "Prototype pollution in lodash"}).IsMalicious() {
		t.Error("una vulnerabilidad normal no es malware")
	}
}

func TestFixedVersion(t *testing.T) {
	v := &Vuln{ID: "X", Affected: []Affected{{}}}
	v.Affected[0].Package.Ecosystem = "npm"
	v.Affected[0].Package.Name = "lodash"
	v.Affected[0].Ranges = []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}{{Type: "SEMVER", Events: []map[string]string{{"introduced": "0"}, {"fixed": "4.17.12"}, {"introduced": "4.18.0"}, {"fixed": "4.18.5"}}}}
	cmp := func(a, b string) int { return semver.CompareStrings(a, b) }
	if got := v.FixedVersion("npm", "lodash", "4.17.5", cmp); got != "4.17.12" {
		t.Errorf("fixed = %q", got)
	}
	if got := v.FixedVersion("npm", "lodash", "4.18.1", cmp); got != "4.18.5" {
		t.Errorf("fixed = %q", got)
	}
	if got := v.FixedVersion("npm", "lodash", "4.19.0", cmp); got != "" {
		t.Errorf("no debería haber versión corregida, pero fue %q", got)
	}
	if got := v.FixedVersion("npm", "otro", "1.0.0", cmp); got != "" {
		t.Errorf("paquete distinto: %q", got)
	}
}

func TestGroupAliases(t *testing.T) {
	vs := []*Vuln{
		{ID: "PYSEC-2021-1", Aliases: []string{"CVE-2021-1", "GHSA-aaaa"}, Summary: "uno"},
		{ID: "GHSA-aaaa", Aliases: []string{"CVE-2021-1"}, Summary: "uno (ghsa)"},
		{ID: "GHSA-bbbb", Aliases: []string{"CVE-2021-2"}},
		{ID: "MAL-2024-9"},
	}
	out := GroupAliases(vs)
	if len(out) != 3 {
		t.Fatalf("esperaba 3 grupos, hay %d", len(out))
	}
	var first *Vuln
	for _, v := range out {
		if v.ID == "GHSA-aaaa" {
			first = v
		}
	}
	if first == nil {
		t.Fatalf("el representante del grupo debe ser el GHSA: %+v", out)
	}
	found := map[string]bool{}
	for _, a := range first.Aliases {
		found[a] = true
	}
	if !found["CVE-2021-1"] || !found["PYSEC-2021-1"] {
		t.Errorf("faltan alias: %v", first.Aliases)
	}
}

func TestQueryBatchAndCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package   struct{ Name, Ecosystem string } `json:"package"`
					Version   string                           `json:"version"`
					PageToken string                           `json:"page_token"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			type res struct {
				Vulns []VulnRef `json:"vulns,omitempty"`
				Next  string    `json:"next_page_token,omitempty"`
			}
			var out struct {
				Results []res `json:"results"`
			}
			for _, q := range req.Queries {
				switch {
				case q.Package.Name == "lodash" && q.PageToken == "":
					out.Results = append(out.Results, res{Vulns: []VulnRef{{ID: "GHSA-1", Modified: "2024-01-01T00:00:00Z"}}, Next: "p2"})
				case q.Package.Name == "lodash" && q.PageToken == "p2":
					out.Results = append(out.Results, res{Vulns: []VulnRef{{ID: "GHSA-2", Modified: "2024-01-01T00:00:00Z"}}})
				default:
					out.Results = append(out.Results, res{})
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/v1/vulns/GHSA-1", "/v1/vulns/GHSA-2":
			calls++
			_ = json.NewEncoder(w).Encode(Vuln{ID: r.URL.Path[len("/v1/vulns/"):], Summary: "x", Modified: "2024-01-01T00:00:00Z"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(httpx.New(5*time.Second, false), srv.URL, cache.New(t.TempDir()))
	refs, err := c.QueryBatch(context.Background(), []Query{{"npm", "lodash", "4.17.0"}, {"npm", "otro", "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs[0]) != 2 || len(refs[1]) != 0 {
		t.Fatalf("la paginación debe unir los resultados: %+v", refs)
	}
	for i := 0; i < 2; i++ {
		got, failed, err := c.FetchVulns(context.Background(), refs[0])
		if err != nil || failed != 0 || len(got) != 2 {
			t.Fatalf("FetchVulns: %v %d %v", got, failed, err)
		}
	}
	if calls != 2 {
		t.Errorf("la segunda pasada debe salir de la caché: %d llamadas", calls)
	}
}
