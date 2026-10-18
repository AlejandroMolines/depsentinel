package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/cache"
	"github.com/AlejandroMolines/depsentinel/internal/httpx"
)

func client() *httpx.Client {
	c := httpx.New(5*time.Second, false)
	c.Retries = 0
	return c
}

const fullPackument = `{
 "name":"@scope/pkg",
 "dist-tags":{"latest":"2.0.0"},
 "modified":"2026-01-01T00:00:00.000Z",
 "time":{"created":"2020-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z","1.1.0":"2021-06-01T00:00:00.000Z","2.0.0":"2026-01-01T00:00:00.000Z"},
 "repository":{"type":"git","url":"git+https://github.com/o/r.git"},
 "versions":{
  "1.0.0":{"version":"1.0.0","_npmUser":{"name":"alice"},"maintainers":[{"name":"alice"}]},
  "1.1.0":{"version":"1.1.0","_npmUser":{"name":"alice"},"maintainers":[{"name":"alice"}],"scripts":{"postinstall":"node x.js","test":"jest"},"deprecated":"usa 2.x","dist":{"tarball":"http://T/t.tgz","integrity":"sha512-abc"}},
  "2.0.0-beta.1":{"version":"2.0.0-beta.1"},
  "2.0.0":{"version":"2.0.0","_npmUser":"bob <bob@x.io>","maintainers":[{"name":"alice"},{"name":"bob"}],"license":{"type":"MIT"}}
 }
}`

func TestNPMMetas(t *testing.T) {
	var hits int32
	var lastAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		lastAccept = r.Header.Get("Accept")
		switch r.URL.EscapedPath() {
		case "/@scope%2Fpkg":
			_, _ = w.Write([]byte(fullPackument))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	n := NewNPM(client(), srv.URL, cache.New(t.TempDir()))

	// versión abreviada: una sola descarga para varias versiones
	m, err := n.Metas(context.Background(), "@scope/pkg", []string{"1.1.0", "1.0.0", "9.9.9"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 || !strings.Contains(lastAccept, "install-v1") {
		t.Errorf("hits=%d accept=%q", hits, lastAccept)
	}
	if !m["9.9.9"].VersionMissing || m["1.1.0"].Deprecated != "usa 2.x" || !m["1.1.0"].HasInstallScript || m["1.1.0"].InstallScripts["postinstall"] != "node x.js" {
		t.Errorf("abreviado: %+v %+v", m["9.9.9"], m["1.1.0"])
	}
	if m["1.0.0"].LastRelease == nil || m["1.0.0"].Latest != "2.0.0" || m["1.0.0"].VersionCount != 4 {
		t.Errorf("modified/latest/versiones: %+v", m["1.0.0"])
	}
	// la segunda llamada sale de la caché
	if _, err := n.Metas(context.Background(), "@scope/pkg", []string{"1.1.0"}, false); err != nil || hits != 1 {
		t.Errorf("caché: hits=%d err=%v", hits, err)
	}
	// deep: publicador, mantenedores nuevos, versión anterior (ignora prereleases)
	d, err := n.Metas(context.Background(), "@scope/pkg", []string{"2.0.0"}, true)
	if err != nil {
		t.Fatal(err)
	}
	x := d["2.0.0"]
	if hits != 2 || !strings.HasPrefix(lastAccept, "application/json") {
		t.Errorf("deep debe pedir el documento completo: hits=%d accept=%q", hits, lastAccept)
	}
	if x.Publisher != "bob" || x.PreviousVersion != "1.1.0" || x.PreviousPublisher != "alice" ||
		len(x.NewMaintainers) != 1 || x.NewMaintainers[0] != "bob" || x.License != "MIT" || x.Created == nil ||
		x.Published == nil || x.Published.Year() != 2026 || x.Repository != "https://github.com/o/r" {
		t.Errorf("deep: %+v", x)
	}
	// paquete inexistente
	miss, err := n.Metas(context.Background(), "no-existe", []string{"1.0.0"}, false)
	if err != nil || !miss["1.0.0"].PackageMissing {
		t.Errorf("404: %+v %v", miss, err)
	}
}

func TestVerifySRIAndTarball(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"package/package.json": "{}", "package/scripts/setup.js": "console.log(1)", "package/../evil": "x"} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	data := buf.Bytes()
	sum := sha512.Sum512(data)
	good := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])

	if err := VerifySRI(data, good); err != nil {
		t.Errorf("hash correcto rechazado: %v", err)
	}
	if err := VerifySRI(data, "sha512-AAAA"); err == nil {
		t.Error("hash incorrecto aceptado")
	}
	if err := VerifySRI(data, "sha1-xyz"); err != nil {
		t.Error("solo se verifica sha512; sha1 se ignora")
	}
	files, err := ExtractTarball(data, 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
	}
	if !got["package.json"] || !got["scripts/setup.js"] || len(got) != 2 {
		t.Errorf("ficheros extraídos (sin prefijo ni rutas con ..): %v", got)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	defer srv.Close()
	n := NewNPM(client(), srv.URL, nil)
	if _, err := n.FetchTarball(context.Background(), srv.URL+"/a.tgz", good); err != nil {
		t.Errorf("descarga con hash correcto: %v", err)
	}
	if _, err := n.FetchTarball(context.Background(), srv.URL+"/a.tgz", "sha512-AAAA"); err == nil {
		t.Error("hash incorrecto")
	} else if _, ok := err.(*ErrIntegrity); !ok {
		t.Errorf("debe ser *ErrIntegrity: %T", err)
	}
	if _, err := n.FetchTarball(context.Background(), "https://otro.example/a.tgz", good); err == nil {
		t.Error("un tarball fuera del host del registry debe rechazarse")
	}
}

func TestPyPIMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/foo/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"info":     map[string]any{"version": "2.0", "project_urls": map[string]string{"Source": "https://github.com/o/foo"}},
				"urls":     []map[string]any{{"packagetype": "bdist_wheel", "upload_time_iso_8601": "2026-10-10T10:00:00.000000Z"}},
				"releases": map[string]any{"1.0": []any{}, "2.0": []any{}},
			})
		case "/pypi/foo/1.0/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{"version": "1.0"},
				"urls": []map[string]any{{"packagetype": "sdist", "yanked": true, "yanked_reason": "roto", "upload_time_iso_8601": "2020-01-01T00:00:00Z"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p := NewPyPI(client(), srv.URL, cache.New(t.TempDir()))
	m, err := p.Meta(context.Background(), "foo", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Yanked || m.YankedReason != "roto" || !m.SdistOnly || m.Latest != "2.0" || m.VersionCount != 2 || m.Repository != "https://github.com/o/foo" ||
		m.Published == nil || m.Published.Year() != 2020 || m.LastRelease == nil || m.LastRelease.Year() != 2026 {
		t.Errorf("meta: %+v", m)
	}
	if v, _ := p.Meta(context.Background(), "foo", "0.5"); v == nil || !v.VersionMissing {
		t.Errorf("versión inexistente: %+v", v)
	}
	if v, _ := p.Meta(context.Background(), "nada", "1"); v == nil || !v.PackageMissing {
		t.Errorf("paquete inexistente: %+v", v)
	}
}

func TestGoProxyAndGitHub(t *testing.T) {
	if got := EscapeModulePath("github.com/Azure/azure-sdk"); got != "github.com/!azure/azure-sdk" {
		t.Errorf("EscapeModulePath = %q", got)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github.com/o/m/@latest":
			_, _ = w.Write([]byte(`{"Version":"v1.5.0","Time":"2026-09-01T00:00:00Z"}`))
		case "/github.com/o/m/@v/v1.0.0.info":
			_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"2021-01-01T00:00:00Z"}`))
		case "/repos/actions/checkout/commits/v4":
			_, _ = w.Write([]byte(`{"sha":"11bd71901bbe5b1630ceea73d27597364c9af683"}`))
		case "/repos/actions/checkout/commits/raro":
			_, _ = w.Write([]byte(`{"sha":"no-es-un-sha"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	g := NewGoProxy(client(), srv.URL, nil)
	m, err := g.Meta(context.Background(), "github.com/o/m", "v1.0.0")
	if err != nil || m.Latest != "v1.5.0" || m.Published.Year() != 2021 || m.LastRelease.Year() != 2026 {
		t.Errorf("goproxy: %+v %v", m, err)
	}
	if m, _ := g.Meta(context.Background(), "github.com/o/m", "v9.9.9"); !m.VersionMissing {
		t.Error("versión inexistente")
	}
	gh := NewGitHub(client(), srv.URL)
	sha, err := gh.ResolveRef(context.Background(), "actions", "checkout", "v4")
	if err != nil || sha != "11bd71901bbe5b1630ceea73d27597364c9af683" {
		t.Errorf("ResolveRef: %q %v", sha, err)
	}
	if _, err := gh.ResolveRef(context.Background(), "actions", "checkout", "raro"); err == nil {
		t.Error("un SHA inválido debe rechazarse")
	}
}
