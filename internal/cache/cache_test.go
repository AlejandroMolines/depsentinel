package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPutGetTTLAndClear(t *testing.T) {
	c := New(t.TempDir())
	if _, ok := c.Get("ns", "k", time.Hour); ok {
		t.Error("una clave nueva no existe")
	}
	if err := c.Put("ns", "k", []byte("hola")); err != nil {
		t.Fatal(err)
	}
	if b, ok := c.Get("ns", "k", time.Hour); !ok || string(b) != "hola" {
		t.Errorf("Get: %q %v", b, ok)
	}
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(c.file("ns", "k"), old, old)
	if _, ok := c.Get("ns", "k", time.Hour); ok {
		t.Error("caducada por TTL")
	}
	if _, ok := c.Get("ns", "k", 0); !ok {
		t.Error("ttl 0 significa sin caducidad")
	}
	type v struct{ A int }
	_ = c.PutJSON("j", "x", v{7})
	var got v
	if !c.GetJSON("j", "x", time.Hour, &got) || got.A != 7 {
		t.Errorf("JSON: %+v", got)
	}
	_ = c.Put("feed", "keep", []byte("x"))
	if err := c.ClearNamespaces("ns", "j"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.Dir(), "ns")); !os.IsNotExist(err) {
		t.Error("ns debe borrarse")
	}
	if _, ok := c.Get("feed", "keep", 0); !ok {
		t.Error("solo se borran los espacios indicados")
	}
	var nilCache *Cache
	if _, ok := nilCache.Get("a", "b", 0); ok || nilCache.Put("a", "b", nil) != nil || nilCache.ClearNamespaces("x") != nil {
		t.Error("un *Cache nil se comporta como sin caché")
	}
}
