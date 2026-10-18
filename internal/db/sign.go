package db

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	dbdata "github.com/AlejandroMolines/depsentinel/db"
)

// GenerateKey crea un par de claves Ed25519 y las devuelve en base64.
func GenerateKey() (pub, priv string, err error) {
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(k), nil
}

// Sign firma data con una clave privada Ed25519 en base64 y devuelve la firma en base64.
func Sign(privB64 string, data []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return "", errors.New("clave privada Ed25519 inválida")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(raw), data)), nil
}

// Verify comprueba una firma Ed25519 (base64) con la clave pública (base64).
func Verify(pubB64 string, data []byte, sigB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("clave pública Ed25519 inválida")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return errors.New("firma con formato inválido")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return errors.New("la firma no corresponde al contenido")
	}
	return nil
}

// EmbeddedPublicKey devuelve la clave pública embebida en el binario ("" si no hay).
func EmbeddedPublicKey() string {
	for _, line := range strings.Split(dbdata.PublicKey, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

type feedIndex struct {
	Schema    int               `json:"schema"`
	Version   string            `json:"version"`
	Generated string            `json:"generated"`
	Files     map[string]string `json:"files"`
}

// FeedFiles son los únicos ficheros que acepta `db update`.
var FeedFiles = []string{"malicious.json", "popular.json"}

// BuildIndex genera index.json con el SHA-256 de cada fichero del feed en dir.
func BuildIndex(dir string, now time.Time) ([]byte, error) {
	idx := feedIndex{Schema: 1, Version: now.UTC().Format("2006.01.02"), Generated: now.UTC().Format(time.RFC3339), Files: map[string]string{}}
	for _, name := range FeedFiles {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		idx.Files[name] = hex.EncodeToString(sum[:])
	}
	out, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var errNoKey = fmt.Errorf("no hay clave pública configurada, así que no puedo verificar la firma del feed.\n" +
	"  Configura la clave con --pubkey <base64> (o feed_public_key en .depsentinel.json),\n" +
	"  o usa --allow-unsigned bajo tu responsabilidad")
