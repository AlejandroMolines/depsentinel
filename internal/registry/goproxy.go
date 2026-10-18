package registry

import (
	"context"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// DefaultGoProxyBase es el proxy público de módulos de Go.
const DefaultGoProxyBase = "https://proxy.golang.org"

// GoProxy consulta un proxy de módulos de Go (protocolo GOPROXY).
type GoProxy struct {
	HTTP  *httpx.Client
	Base  string
	Cache *cache.Cache
	TTL   time.Duration
}

// NewGoProxy crea un cliente del proxy de Go.
func NewGoProxy(h *httpx.Client, base string, c *cache.Cache) *GoProxy {
	if base == "" {
		base = DefaultGoProxyBase
	}
	return &GoProxy{HTTP: h, Base: strings.TrimRight(base, "/"), Cache: c, TTL: 12 * time.Hour}
}

type goInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// EscapeModulePath codifica mayúsculas como "!minúscula", como exige el protocolo GOPROXY.
func EscapeModulePath(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (g *GoProxy) info(ctx context.Context, module, suffix string) (*goInfo, error) {
	var i goInfo
	if err := g.HTTP.GetJSON(ctx, g.Base+"/"+EscapeModulePath(module)+"/"+suffix, nil, &i); err != nil {
		return nil, err
	}
	return &i, nil
}

// Meta devuelve fechas de publicación de un módulo y de su última versión.
func (g *GoProxy) Meta(ctx context.Context, module, version string) (*model.Meta, error) {
	key := module + "@" + version
	var cached model.Meta
	if g.Cache.GetJSON("goproxy", key, g.TTL, &cached) {
		return &cached, nil
	}
	latest, err := g.info(ctx, module, "@latest")
	if err != nil {
		if httpx.IsNotFound(err) {
			m := &model.Meta{PackageMissing: true, Deep: true}
			_ = g.Cache.PutJSON("goproxy", key, m)
			return m, nil
		}
		return nil, err
	}
	lt := latest.Time
	m := &model.Meta{Deep: true, Latest: latest.Version, LastRelease: &lt}
	if version == latest.Version {
		m.Published = &lt
	} else {
		cur, err := g.info(ctx, module, "@v/"+EscapeModulePath(version)+".info")
		if err != nil {
			if httpx.IsNotFound(err) {
				m.VersionMissing = true
				_ = g.Cache.PutJSON("goproxy", key, m)
				return m, nil
			}
			return nil, err
		}
		ct := cur.Time
		m.Published = &ct
	}
	_ = g.Cache.PutJSON("goproxy", key, m)
	return m, nil
}
