// Package cache implementa una caché en disco sencilla (clave -> bytes, con TTL).
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Cache guarda ficheros bajo un directorio. Un *Cache nil se comporta como "sin caché".
type Cache struct {
	dir string
}

// New crea una caché en el directorio indicado (se crea al escribir).
func New(dir string) *Cache { return &Cache{dir: dir} }

// Default devuelve la caché por defecto: DEPSENTINEL_CACHE_DIR o el directorio de caché del usuario.
func Default() *Cache {
	if d := os.Getenv("DEPSENTINEL_CACHE_DIR"); d != "" {
		return New(d)
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return New(filepath.Join(base, "depsentinel"))
}

// Dir devuelve el directorio raíz de la caché.
func (c *Cache) Dir() string {
	if c == nil {
		return ""
	}
	return c.dir
}

func (c *Cache) file(ns, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, ns, hex.EncodeToString(sum[:])+".json")
}

// Get lee una entrada si existe y no ha caducado (ttl <= 0 significa sin caducidad).
func (c *Cache) Get(ns, key string, ttl time.Duration) ([]byte, bool) {
	if c == nil || c.dir == "" {
		return nil, false
	}
	p := c.file(ns, key)
	st, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if ttl > 0 && time.Since(st.ModTime()) > ttl {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Put guarda una entrada de forma atómica.
func (c *Cache) Put(ns, key string, data []byte) error {
	if c == nil || c.dir == "" {
		return nil
	}
	p := c.file(ns, key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, p); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// GetJSON lee y decodifica una entrada JSON.
func (c *Cache) GetJSON(ns, key string, ttl time.Duration, v any) bool {
	b, ok := c.Get(ns, key, ttl)
	if !ok {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

// PutJSON codifica y guarda una entrada JSON.
func (c *Cache) PutJSON(ns, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Put(ns, key, b)
}

// ClearNamespaces borra solo los espacios de nombres indicados (nunca el directorio raíz).
func (c *Cache) ClearNamespaces(names ...string) error {
	if c == nil || c.dir == "" {
		return nil
	}
	for _, n := range names {
		if err := os.RemoveAll(filepath.Join(c.dir, n)); err != nil {
			return err
		}
	}
	return nil
}
