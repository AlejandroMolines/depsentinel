// Package api expone DepSentinel como librería: escanear un directorio y actualizar la base de datos
// desde otro programa Go (por ejemplo un servicio interno, un plugin de CI o una extensión de editor).
//
//	c := api.New(api.WithOffline())
//	rep, err := c.Scan(ctx, "./mi-proyecto")
//	if err == nil && rep.Count(api.SeverityHigh) > 0 { ... }
package api

import (
	"context"
	"path/filepath"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/allowlist"
	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/config"
	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/engine"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// Tipos públicos (alias de los internos, estables entre versiones menores).
type (
	// Report es el resultado de un escaneo.
	Report = model.Report
	// Finding es un problema detectado.
	Finding = model.Finding
	// Package es una dependencia analizada.
	Package = model.Package
	// Severity es el nivel de riesgo de un hallazgo.
	Severity = model.Severity
	// Ecosystem identifica el gestor de paquetes.
	Ecosystem = model.Ecosystem
)

// Severidades y ecosistemas.
const (
	SeverityLow      = model.SeverityLow
	SeverityMedium   = model.SeverityMedium
	SeverityHigh     = model.SeverityHigh
	SeverityCritical = model.SeverityCritical

	NPM     = model.NPM
	PyPI    = model.PyPI
	Go      = model.Go
	Docker  = model.Docker
	Actions = model.Actions
)

type settings struct {
	offline, deep, prodOnly bool
	noOSV, noRegistry       bool
	ecosystems              []Ecosystem
	configFile, allowFile   string
	cacheDir                string
	timeout                 time.Duration
}

// Option personaliza un Client.
type Option func(*settings)

// WithOffline evita cualquier acceso a la red (solo reglas locales).
func WithOffline() Option { return func(s *settings) { s.offline = true } }

// WithDeep descarga e inspecciona los paquetes npm con scripts de instalación.
func WithDeep() Option { return func(s *settings) { s.deep = true } }

// WithProdOnly ignora las dependencias de desarrollo.
func WithProdOnly() Option { return func(s *settings) { s.prodOnly = true } }

// WithEcosystems limita el análisis a estos ecosistemas.
func WithEcosystems(e ...Ecosystem) Option { return func(s *settings) { s.ecosystems = e } }

// WithConfigFile usa este .depsentinel.json en lugar de buscarlo en el proyecto.
func WithConfigFile(path string) Option { return func(s *settings) { s.configFile = path } }

// WithAllowlistFile usa esta lista blanca en lugar de la indicada en la configuración.
func WithAllowlistFile(path string) Option { return func(s *settings) { s.allowFile = path } }

// WithCacheDir cambia el directorio de caché.
func WithCacheDir(dir string) Option { return func(s *settings) { s.cacheDir = dir } }

// WithTimeout cambia el timeout de las peticiones HTTP.
func WithTimeout(d time.Duration) Option { return func(s *settings) { s.timeout = d } }

// Client ejecuta escaneos con unas opciones fijas.
type Client struct{ s settings }

// New crea un cliente.
func New(opts ...Option) *Client {
	c := &Client{}
	for _, o := range opts {
		o(&c.s)
	}
	return c
}

func (c *Client) cache() *cache.Cache {
	if c.s.cacheDir != "" {
		return cache.New(c.s.cacheDir)
	}
	return cache.Default()
}

// Scan analiza el directorio (o fichero) indicado.
func (c *Client) Scan(ctx context.Context, dir string) (*Report, error) {
	cfgPath := c.s.configFile
	if cfgPath == "" {
		cfgPath = config.Find(dir)
	}
	cfg := config.Default()
	base := dir
	if cfgPath != "" {
		loaded, err := config.Load(cfgPath)
		if err != nil {
			return nil, err
		}
		cfg, base = loaded, filepath.Dir(cfgPath)
	}
	if c.s.timeout > 0 {
		cfg.Network.TimeoutSeconds = int(c.s.timeout.Seconds())
	}
	alPath := c.s.allowFile
	if alPath == "" {
		alPath = cfg.AllowlistFile
		if !filepath.IsAbs(alPath) {
			alPath = filepath.Join(base, alPath)
		}
	}
	al, err := allowlist.Load(alPath)
	if err != nil {
		return nil, err
	}
	ch := c.cache()
	store, err := db.Load(ch.Dir())
	if err != nil {
		return nil, err
	}
	res, err := engine.Scan(ctx, engine.Options{
		Dir: dir, Ecosystems: c.s.ecosystems, Offline: c.s.offline, NoOSV: c.s.noOSV, NoRegistry: c.s.noRegistry,
		Deep: c.s.deep, ProdOnly: c.s.prodOnly, Config: cfg, Allowlist: al, Store: store, Cache: ch,
		Endpoints: config.EndpointsFromEnv(),
	})
	if err != nil {
		return nil, err
	}
	return res.Report, nil
}

// UpdateDB descarga el feed de la base de datos (feedURL vacío usa el oficial) y verifica su firma
// con pubKey (base64 Ed25519; vacío usa la clave embebida en el binario).
func (c *Client) UpdateDB(ctx context.Context, feedURL, pubKey string) (version string, signed bool, err error) {
	timeout := c.s.timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	res, err := db.Update(ctx, db.UpdateOptions{
		FeedURL: feedURL, PublicKey: pubKey, CacheDir: c.cache().Dir(),
		HTTP: httpx.New(timeout, c.s.offline), Now: time.Now(),
	})
	if err != nil {
		return "", false, err
	}
	return res.Version, res.Signed, nil
}
