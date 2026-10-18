package registry

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// DefaultPyPIBase es la API JSON pública de PyPI.
const DefaultPyPIBase = "https://pypi.org"

// PyPI consulta la API JSON de PyPI.
type PyPI struct {
	HTTP  *httpx.Client
	Base  string
	Cache *cache.Cache
	TTL   time.Duration
}

// NewPyPI crea un cliente de PyPI.
func NewPyPI(h *httpx.Client, base string, c *cache.Cache) *PyPI {
	if base == "" {
		base = DefaultPyPIBase
	}
	return &PyPI{HTTP: h, Base: strings.TrimRight(base, "/"), Cache: c, TTL: 12 * time.Hour}
}

type pypiFile struct {
	PackageType  string `json:"packagetype"`
	UploadTime   string `json:"upload_time_iso_8601"`
	Yanked       bool   `json:"yanked"`
	YankedReason string `json:"yanked_reason"`
}

type pypiDoc struct {
	Info struct {
		Version     string            `json:"version"`
		ProjectURLs map[string]string `json:"project_urls"`
		HomePage    string            `json:"home_page"`
	} `json:"info"`
	URLs     []pypiFile                 `json:"urls"`
	Releases map[string]json.RawMessage `json:"releases"`
}

func (p *PyPI) get(ctx context.Context, path string) (*pypiDoc, error) {
	var d pypiDoc
	if err := p.HTTP.GetJSON(ctx, p.Base+path, nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func earliestUpload(files []pypiFile) *time.Time {
	var best *time.Time
	for _, f := range files {
		if t := parseTime(f.UploadTime); t != nil && (best == nil || t.Before(*best)) {
			best = t
		}
	}
	return best
}

// Meta devuelve los metadatos de name==version (name debe estar normalizado).
func (p *PyPI) Meta(ctx context.Context, name, version string) (*model.Meta, error) {
	key := name + "@" + version
	var cached model.Meta
	if p.Cache.GetJSON("pypi", key, p.TTL, &cached) {
		return &cached, nil
	}
	latest, err := p.get(ctx, "/pypi/"+url.PathEscape(name)+"/json")
	if err != nil {
		if httpx.IsNotFound(err) {
			m := &model.Meta{PackageMissing: true, Deep: true}
			_ = p.Cache.PutJSON("pypi", key, m)
			return m, nil
		}
		return nil, err
	}
	m := &model.Meta{Deep: true, Latest: latest.Info.Version, LastRelease: earliestUpload(latest.URLs), VersionCount: len(latest.Releases)}
	for k, v := range latest.Info.ProjectURLs {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "source") || strings.Contains(lk, "repository") || strings.Contains(lk, "github") {
			m.Repository = v
			break
		}
	}
	if m.Repository == "" {
		m.Repository = latest.Info.HomePage
	}
	cur := latest
	if version != "" && version != latest.Info.Version {
		cur, err = p.get(ctx, "/pypi/"+url.PathEscape(name)+"/"+url.PathEscape(version)+"/json")
		if err != nil {
			if httpx.IsNotFound(err) {
				m.VersionMissing = true
				_ = p.Cache.PutJSON("pypi", key, m)
				return m, nil
			}
			return nil, err
		}
	}
	m.Published = earliestUpload(cur.URLs)
	if len(cur.URLs) > 0 {
		allYanked, hasWheel := true, false
		for _, f := range cur.URLs {
			if !f.Yanked {
				allYanked = false
			} else if m.YankedReason == "" {
				m.YankedReason = f.YankedReason
			}
			if f.PackageType == "bdist_wheel" {
				hasWheel = true
			}
		}
		m.Yanked = allYanked
		m.SdistOnly = !hasWheel
	}
	_ = p.Cache.PutJSON("pypi", key, m)
	return m, nil
}
