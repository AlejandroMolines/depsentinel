package api_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AlejandroMolines/depsentinel/pkg/api"
)

func TestScanOffline(t *testing.T) {
	dir := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{"":{"dependencies":{"crossenv":"1.0.0"}},
	 "node_modules/crossenv":{"version":"1.0.0","resolved":"https://registry.npmjs.org/crossenv/-/crossenv-1.0.0.tgz","integrity":"sha512-AAAA"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	c := api.New(api.WithOffline(), api.WithCacheDir(t.TempDir()), api.WithEcosystems(api.NPM))
	rep, err := c.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Count(api.SeverityCritical) != 1 || rep.Findings[0].Package != "crossenv" {
		t.Errorf("hallazgos: %+v", rep.Findings)
	}
	if _, err := c.Scan(context.Background(), filepath.Join(dir, "no-existe")); err == nil {
		t.Error("un directorio inexistente es un error")
	}
}
