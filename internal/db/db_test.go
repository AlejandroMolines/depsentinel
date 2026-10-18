package db

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/httpx"
	"github.com/AlejandroMolines/depsentinel/internal/model"
)

func TestSeedLookups(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.LookupMalicious(model.NPM, "event-stream", "3.3.6")) != 1 {
		t.Error("event-stream@3.3.6 debe estar en la semilla")
	}
	if len(s.LookupMalicious(model.NPM, "event-stream", "3.3.5")) != 0 {
		t.Error("event-stream@3.3.5 no está afectada")
	}
	if len(s.LookupMalicious(model.NPM, "crossenv", "1.0.0")) != 1 || len(s.LookupMalicious(model.NPM, "crossenv", "")) != 1 {
		t.Error("crossenv: todas las versiones")
	}
	if len(s.LookupMalicious(model.PyPI, "Python3_Dateutil", "1.0")) != 1 {
		t.Error("los nombres de PyPI se normalizan (PEP 503)")
	}
	if len(s.LookupMalicious(model.NPM, "chalk", "5.6.1")) != 1 || len(s.LookupMalicious(model.NPM, "chalk", "5.3.0")) != 0 {
		t.Error("chalk 5.6.1 sí, 5.3.0 no")
	}
	if !s.IsPopular(model.NPM, "React") || s.IsPopular(model.NPM, "reactt") {
		t.Error("IsPopular")
	}
	if !s.IsPopular(model.Docker, "docker.io/library/nginx") {
		t.Error("los nombres de Docker se normalizan")
	}
	if !s.IsBenign(model.NPM, "@esbuild/linux-x64", "install-script") || s.IsBenign(model.NPM, "esbuild", "typosquat") {
		t.Error("IsBenign con patrones y reglas")
	}
	if s.Info().MaliciousEntries < 20 {
		t.Errorf("Info: %+v", s.Info())
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(priv, []byte("hola"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, []byte("hola"), sig); err != nil {
		t.Errorf("firma válida rechazada: %v", err)
	}
	if err := Verify(pub, []byte("hola!"), sig); err == nil {
		t.Error("contenido alterado debe fallar")
	}
	if _, err := Sign("basura", []byte("x")); err == nil {
		t.Error("clave privada inválida")
	}
}

func feedServer(t *testing.T, dir string, sigB64 string, tamper bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "index.json.sig" {
			_, _ = w.Write([]byte(sigB64))
			return
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if tamper && name == "malicious.json" {
			b = append(b, ' ')
		}
		_, _ = w.Write(b)
	}))
}

func TestUpdateFlow(t *testing.T) {
	feed := t.TempDir()
	mal := `{"schema":1,"updated":"2026-10-20","entries":[{"id":"DS-9999","ecosystem":"npm","name":"nuevo-malo","versions":["*"],"kind":"malware","summary":"prueba"}]}`
	pop := `{"schema":1,"updated":"2026-10-20","packages":{"npm":["paquete-nuevo-popular"]}}`
	_ = os.WriteFile(filepath.Join(feed, "malicious.json"), []byte(mal), 0o644)
	_ = os.WriteFile(filepath.Join(feed, "popular.json"), []byte(pop), 0o644)
	idx, err := BuildIndex(feed, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(feed, "index.json"), idx, 0o644)
	pub, priv, _ := GenerateKey()
	sig, _ := Sign(priv, idx)
	h := httpx.New(5*time.Second, false)
	h.Retries = 0

	srv := feedServer(t, feed, sig, false)
	defer srv.Close()
	cache := t.TempDir()
	res, err := Update(context.Background(), UpdateOptions{FeedURL: srv.URL, PublicKey: pub, CacheDir: cache, HTTP: h, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Signed || len(res.Files) != 2 || res.Version != "2026.10.20" {
		t.Errorf("resultado: %+v", res)
	}
	s, err := Load(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.LookupMalicious(model.NPM, "nuevo-malo", "1.0.0")) != 1 || !s.IsPopular(model.NPM, "paquete-nuevo-popular") {
		t.Error("el feed descargado debe fusionarse con la semilla")
	}
	if len(s.LookupMalicious(model.NPM, "event-stream", "3.3.6")) != 1 {
		t.Error("la semilla debe seguir presente")
	}
	if s.Info().Feed == nil || !s.Info().Feed.Signed {
		t.Errorf("meta del feed: %+v", s.Info().Feed)
	}

	// firma de otra clave
	otherPub, _, _ := GenerateKey()
	if _, err := Update(context.Background(), UpdateOptions{FeedURL: srv.URL, PublicKey: otherPub, CacheDir: t.TempDir(), HTTP: h, Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "firma") {
		t.Errorf("con otra clave debe fallar: %v", err)
	}
	// sin clave configurada
	if _, err := Update(context.Background(), UpdateOptions{FeedURL: srv.URL, CacheDir: t.TempDir(), HTTP: h, Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "clave pública") {
		t.Errorf("sin clave debe fallar con una explicación: %v", err)
	}
	// sin firma pero permitido explícitamente
	res, err = Update(context.Background(), UpdateOptions{FeedURL: srv.URL, AllowUnsigned: true, CacheDir: t.TempDir(), HTTP: h, Now: time.Now()})
	if err != nil || res.Signed {
		t.Errorf("allow-unsigned: %+v %v", res, err)
	}
	// contenido manipulado: el hash no coincide con el índice firmado
	bad := feedServer(t, feed, sig, true)
	defer bad.Close()
	if _, err := Update(context.Background(), UpdateOptions{FeedURL: bad.URL, PublicKey: pub, CacheDir: t.TempDir(), HTTP: h, Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Errorf("un fichero alterado debe rechazarse: %v", err)
	}
	// solo https (salvo localhost)
	if _, err := Update(context.Background(), UpdateOptions{FeedURL: "http://example.com/db", PublicKey: pub, CacheDir: t.TempDir(), HTTP: h, Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("http remoto debe rechazarse: %v", err)
	}
}

func TestCorruptFeedIgnored(t *testing.T) {
	cache := t.TempDir()
	_ = os.MkdirAll(filepath.Join(cache, "feed"), 0o755)
	_ = os.WriteFile(filepath.Join(cache, "feed", "malicious.json"), []byte("{no es json"), 0o644)
	s, err := Load(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.LookupMalicious(model.NPM, "crossenv", "")) != 1 {
		t.Error("un feed corrupto no debe romper la semilla")
	}
	var probe map[string]any
	_ = json.Unmarshal([]byte(`{}`), &probe)
}
