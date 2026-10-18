package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/httpx"
)

// DefaultFeedURL es el directorio db/ del repositorio (cambia "AlejandroMolines" por tu usuario real).
const DefaultFeedURL = "https://raw.githubusercontent.com/AlejandroMolines/depsentinel/main/db"

const maxFeedFile = 20 << 20

// UpdateOptions configura `db update`.
type UpdateOptions struct {
	FeedURL       string
	PublicKey     string
	AllowUnsigned bool
	CacheDir      string
	HTTP          *httpx.Client
	Now           time.Time
}

// UpdateResult resume lo descargado.
type UpdateResult struct {
	Version string
	Signed  bool
	Files   []string
	Source  string
}

func checkFeedURL(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("URL de feed inválida: %q", base)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return nil
	}
	return fmt.Errorf("el feed debe usar https (recibido %q)", base)
}

// Update descarga el feed, verifica firma y hashes, y lo guarda en cacheDir/feed.
func Update(ctx context.Context, o UpdateOptions) (*UpdateResult, error) {
	if o.CacheDir == "" {
		return nil, errors.New("no hay directorio de caché donde guardar el feed")
	}
	base := strings.TrimRight(o.FeedURL, "/")
	if base == "" {
		base = DefaultFeedURL
	}
	if err := checkFeedURL(base); err != nil {
		return nil, err
	}
	idxBytes, err := o.HTTP.GetBytes(ctx, base+"/index.json", nil)
	if err != nil {
		return nil, fmt.Errorf("no se pudo descargar el índice del feed: %w", err)
	}
	if len(idxBytes) > 1<<20 {
		return nil, errors.New("el índice del feed es demasiado grande")
	}
	pub := strings.TrimSpace(o.PublicKey)
	if pub == "" {
		pub = EmbeddedPublicKey()
	}
	signed := false
	switch {
	case pub != "":
		sig, err := o.HTTP.GetBytes(ctx, base+"/index.json.sig", nil)
		if err != nil {
			return nil, fmt.Errorf("falta la firma del feed (index.json.sig): %w", err)
		}
		if err := Verify(pub, idxBytes, string(sig)); err != nil {
			return nil, fmt.Errorf("la firma del feed NO es válida: %w", err)
		}
		signed = true
	case o.AllowUnsigned:
	default:
		return nil, errNoKey
	}
	var idx feedIndex
	if err := json.Unmarshal(idxBytes, &idx); err != nil || idx.Schema != 1 {
		return nil, errors.New("feed index with unknown format")
	}
	dir := filepath.Join(o.CacheDir, "feed")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	res := &UpdateResult{Version: idx.Version, Signed: signed, Source: base}
	staged := map[string][]byte{}
	for _, name := range FeedFiles {
		want, ok := idx.Files[name]
		if !ok {
			continue
		}
		b, err := o.HTTP.GetBytes(ctx, base+"/"+name, nil)
		if err != nil {
			return nil, fmt.Errorf("no se pudo descargar %s: %w", name, err)
		}
		if len(b) > maxFeedFile {
			return nil, fmt.Errorf("%s es demasiado grande", name)
		}
		if got := sha256Hex(b); !strings.EqualFold(got, want) {
			return nil, fmt.Errorf("el hash de %s no coincide con el índice", name)
		}
		var probe struct {
			Schema int `json:"schema"`
		}
		if err := json.Unmarshal(b, &probe); err != nil || probe.Schema != 1 {
			return nil, fmt.Errorf("%s has an unknown format", name)
		}
		staged[name] = b
	}
	if len(staged) == 0 {
		return nil, errors.New("el feed no contiene ficheros reconocidos")
	}
	for name, b := range staged {
		tmp := filepath.Join(dir, name+".tmp")
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return nil, err
		}
		res.Files = append(res.Files, name)
	}
	meta, _ := json.MarshalIndent(FeedMeta{Version: idx.Version, Source: base, Signed: signed, Checked: o.Now.UTC()}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o644); err != nil {
		return nil, err
	}
	return res, nil
}
