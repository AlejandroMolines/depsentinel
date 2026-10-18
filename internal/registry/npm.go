// Package registry consulta los registries públicos (npm, PyPI, proxy de Go, GitHub).
package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/semver"
)

// DefaultNPMBase es el registry público de npm.
const DefaultNPMBase = "https://registry.npmjs.org"

const abbreviatedAccept = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

// NPM consulta un registry compatible con npm.
type NPM struct {
	HTTP  *httpx.Client
	Base  string
	Cache *cache.Cache
	TTL   time.Duration
}

// NewNPM crea un cliente de npm.
func NewNPM(h *httpx.Client, base string, c *cache.Cache) *NPM {
	if base == "" {
		base = DefaultNPMBase
	}
	return &NPM{HTTP: h, Base: strings.TrimRight(base, "/"), Cache: c, TTL: 12 * time.Hour}
}

type packument struct {
	DistTags   map[string]string          `json:"dist-tags"`
	Modified   string                     `json:"modified"`
	Time       map[string]string          `json:"time"`
	Versions   map[string]json.RawMessage `json:"versions"`
	Repository json.RawMessage            `json:"repository"`
}

type versionDoc struct {
	Deprecated       json.RawMessage            `json:"deprecated"`
	HasInstallScript bool                       `json:"hasInstallScript"`
	Scripts          map[string]json.RawMessage `json:"scripts"`
	NpmUser          json.RawMessage            `json:"_npmUser"`
	Maintainers      json.RawMessage            `json:"maintainers"`
	Repository       json.RawMessage            `json:"repository"`
	License          json.RawMessage            `json:"license"`
	Dist             struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

func userName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var u struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &u) == nil && u.Name != "" {
		return u.Name
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(strings.SplitN(s, "<", 2)[0])
	}
	return ""
}

func userNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var out []string
		for _, r := range list {
			if n := userName(r); n != "" {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	if n := userName(raw); n != "" {
		return []string{n}
	}
	return nil
}

func deprecatedMsg(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil && b {
		return "deprecated"
	}
	return ""
}

func repoURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		var o struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(raw, &o) != nil {
			return ""
		}
		s = o.URL
	}
	s = strings.TrimPrefix(strings.TrimSpace(s), "git+")
	return strings.TrimSuffix(s, ".git")
}

func licenseStr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.Type
	}
	return ""
}

func (n *NPM) fetchPackument(ctx context.Context, name string, full bool) (*packument, error) {
	u := n.Base + "/" + url.PathEscape(name)
	accept := "application/json"
	if !full {
		accept = abbreviatedAccept
	}
	data, err := n.HTTP.GetBytes(ctx, u, map[string]string{"Accept": accept})
	if err != nil {
		return nil, err
	}
	var p packument
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("respuesta de npm inválida para %s: %w", name, err)
	}
	return &p, nil
}

// Metas obtiene los metadatos de varias versiones de un mismo paquete con una sola descarga.
// Con deep=true descarga el documento completo (publicador, scripts, fechas).
func (n *NPM) Metas(ctx context.Context, name string, versions []string, deep bool) (map[string]*model.Meta, error) {
	out := map[string]*model.Meta{}
	var missing []string
	for _, v := range versions {
		var m model.Meta
		if n.Cache.GetJSON("npm", name+"@"+v, n.TTL, &m) && (m.Deep || !deep) {
			mm := m
			out[v] = &mm
			continue
		}
		missing = append(missing, v)
	}
	if len(missing) == 0 {
		return out, nil
	}
	p, err := n.fetchPackument(ctx, name, deep)
	if err != nil {
		if httpx.IsNotFound(err) {
			for _, v := range missing {
				m := &model.Meta{PackageMissing: true, Deep: deep}
				out[v] = m
				_ = n.Cache.PutJSON("npm", name+"@"+v, m)
			}
			return out, nil
		}
		return out, err
	}
	for _, v := range missing {
		m := buildNPMMeta(p, v, deep)
		out[v] = m
		_ = n.Cache.PutJSON("npm", name+"@"+v, m)
	}
	return out, nil
}

func buildNPMMeta(p *packument, version string, deep bool) *model.Meta {
	m := &model.Meta{Deep: deep, Latest: p.DistTags["latest"], VersionCount: len(p.Versions)}
	if deep {
		m.Created = parseTime(p.Time["created"])
	}
	if deep {
		if t := parseTime(p.Time[m.Latest]); t != nil {
			m.LastRelease = t
		} else {
			m.LastRelease = latestFromTimes(p.Time)
		}
	} else if t := parseTime(p.Modified); t != nil {
		m.LastRelease = t
	} else {
		m.LastRelease = parseTime(p.Time["modified"])
	}
	raw, ok := p.Versions[version]
	if !ok {
		m.VersionMissing = true
		return m
	}
	var vd versionDoc
	_ = json.Unmarshal(raw, &vd)
	m.Deprecated = deprecatedMsg(vd.Deprecated)
	m.HasInstallScript = vd.HasInstallScript
	scripts := map[string]string{}
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if r, ok := vd.Scripts[k]; ok {
			var s string
			if json.Unmarshal(r, &s) == nil && strings.TrimSpace(s) != "" {
				scripts[k] = s
			}
		}
	}
	if len(scripts) > 0 {
		m.InstallScripts = scripts
		m.HasInstallScript = true
	}
	if !deep {
		return m
	}
	m.Publisher = userName(vd.NpmUser)
	m.Maintainers = userNames(vd.Maintainers)
	m.License = licenseStr(vd.License)
	m.Repository = repoURL(vd.Repository)
	if m.Repository == "" {
		m.Repository = repoURL(p.Repository)
	}
	m.Tarball = vd.Dist.Tarball
	m.RegistryIntegrity = vd.Dist.Integrity
	m.Published = parseTime(p.Time[version])
	if prev := previousVersion(p.Versions, version); prev != "" {
		m.PreviousVersion = prev
		var pd versionDoc
		_ = json.Unmarshal(p.Versions[prev], &pd)
		m.PreviousPublisher = userName(pd.NpmUser)
		m.NewMaintainers = diffNames(m.Maintainers, userNames(pd.Maintainers))
	}
	return m
}

func latestFromTimes(times map[string]string) *time.Time {
	var best *time.Time
	for k, v := range times {
		if k == "created" || k == "modified" {
			continue
		}
		if t := parseTime(v); t != nil && (best == nil || t.After(*best)) {
			best = t
		}
	}
	return best
}

// previousVersion devuelve la mayor versión estrictamente anterior a la indicada.
func previousVersion(versions map[string]json.RawMessage, current string) string {
	cur, ok := semver.Parse(current)
	if !ok {
		return ""
	}
	var best semver.Version
	bestStr := ""
	for s := range versions {
		v, ok := semver.Parse(s)
		if !ok || (v.IsPrerelease() && !cur.IsPrerelease()) {
			continue
		}
		if semver.Compare(v, cur) >= 0 {
			continue
		}
		if bestStr == "" || semver.Compare(v, best) > 0 {
			best, bestStr = v, s
		}
	}
	return bestStr
}

func diffNames(now, before []string) []string {
	if len(before) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, b := range before {
		set[b] = true
	}
	var out []string
	for _, n := range now {
		if !set[n] {
			out = append(out, n)
		}
	}
	return out
}

// MaxTarballSize es el tamaño máximo de un tarball que se descarga en modo deep.
const MaxTarballSize = 25 << 20

// FetchTarball descarga un tarball y comprueba su hash SRI (sha512) si se indica.
// Solo permite URLs del mismo host que el registry configurado.
func (n *NPM) FetchTarball(ctx context.Context, tarballURL, integrity string) ([]byte, error) {
	tu, err := url.Parse(tarballURL)
	if err != nil {
		return nil, err
	}
	bu, err := url.Parse(n.Base)
	if err != nil {
		return nil, err
	}
	if tu.Host != bu.Host {
		return nil, fmt.Errorf("el tarball está en %s, fuera del registry %s", tu.Host, bu.Host)
	}
	data, err := n.HTTP.GetBytes(ctx, tarballURL, nil)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxTarballSize {
		return nil, fmt.Errorf("tarball demasiado grande (%d bytes)", len(data))
	}
	if err := VerifySRI(data, integrity); err != nil {
		return data, err
	}
	return data, nil
}

// ErrIntegrity indica que el hash no coincide.
type ErrIntegrity struct{ Want, Got string }

func (e *ErrIntegrity) Error() string {
	return fmt.Sprintf("el hash del tarball (%s) no coincide con el esperado (%s)", e.Got, e.Want)
}

// VerifySRI comprueba un hash "sha512-<base64>". Si no es sha512 o está vacío no verifica nada.
func VerifySRI(data []byte, integrity string) error {
	for _, tok := range strings.Fields(integrity) {
		if !strings.HasPrefix(tok, "sha512-") {
			continue
		}
		sum := sha512.Sum512(data)
		got := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
		if got != tok {
			return &ErrIntegrity{Want: tok, Got: got}
		}
		return nil
	}
	return nil
}

// TarFile es un fichero extraído de un tarball.
type TarFile struct {
	Path string
	Data []byte
}

// ExtractTarball extrae en memoria los ficheros de un .tgz de npm (sin el prefijo "package/").
// Limita el número de ficheros y el tamaño de cada uno.
func ExtractTarball(data []byte, maxFileSize int64, maxFiles int) ([]TarFile, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out []TarFile
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if h.Typeflag != tar.TypeReg || len(out) >= maxFiles {
			continue
		}
		name := h.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || strings.Contains(name, "..") {
			continue
		}
		if h.Size > maxFileSize {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFileSize))
		if err != nil {
			return out, err
		}
		out = append(out, TarFile{Path: name, Data: b})
	}
	return out, nil
}
