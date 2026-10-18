// Command dbtool son las herramientas de mantenimiento del feed de la base de datos:
// generar claves, validar los ficheros y firmar el índice que descarga `depsentinel db update`.
//
//	go run ./cmd/dbtool keygen
//	go run ./cmd/dbtool check -dir db
//	go run ./cmd/dbtool sign  -dir db -key depsentinel-feed.key
//	go run ./cmd/dbtool verify -dir db -pub <clave pública base64>
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/model"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `dbtool — mantenimiento del feed de DepSentinel

  keygen [-out depsentinel-feed.key]   genera un par de claves Ed25519
  check  [-dir db]                     valida malicious.json y popular.json
  sign   [-dir db] -key FICHERO        regenera index.json y su firma index.json.sig
  verify [-dir db] -pub CLAVE          comprueba la firma del índice y los hashes`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "depsentinel-feed.key", "fichero donde guardar la clave privada")
	_ = fs.Parse(args)
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s ya existe: no lo sobrescribo", *out)
	}
	pub, priv, err := db.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(priv+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("Clave privada guardada en %s (permisos 0600). NO la subas al repositorio:\n", *out)
	fmt.Println("  guárdala como secreto (por ejemplo DB_SIGNING_KEY en GitHub Actions) y haz copia de seguridad.")
	fmt.Printf("\npublic: %s\n\n", pub)
	fmt.Println("Pega esa clave pública en db/pubkey.txt (una línea) y recompila el binario.")
	return nil
}

var validKinds = map[string]bool{"malware": true, "compromised": true, "sabotage": true, "protestware": true}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("dir", "db", "directorio del feed")
	_ = fs.Parse(args)
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	var mal struct {
		Schema  int `json:"schema"`
		Entries []struct {
			ID        string `json:"id"`
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			Summary   string `json:"summary"`
		} `json:"entries"`
	}
	if err := readJSON(filepath.Join(*dir, "malicious.json"), &mal); err != nil {
		return err
	}
	if mal.Schema != 1 {
		add("malicious.json: schema debe ser 1")
	}
	ids := map[string]bool{}
	for i, e := range mal.Entries {
		where := fmt.Sprintf("malicious.json entrada %d (%s)", i+1, e.Name)
		if e.ID == "" || ids[e.ID] {
			add("%s: id vacío o repetido (%q)", where, e.ID)
		}
		ids[e.ID] = true
		if _, ok := model.ParseEcosystem(e.Ecosystem); !ok {
			add("%s: ecosistema desconocido %q", where, e.Ecosystem)
		}
		if strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.Summary) == "" {
			add("%s: faltan name o summary", where)
		}
		if !validKinds[e.Kind] {
			add("%s: kind debe ser malware, compromised, sabotage o protestware", where)
		}
	}
	var pop struct {
		Schema   int                 `json:"schema"`
		Packages map[string][]string `json:"packages"`
	}
	if err := readJSON(filepath.Join(*dir, "popular.json"), &pop); err != nil {
		return err
	}
	if pop.Schema != 1 {
		add("popular.json: schema debe ser 1")
	}
	for eco, names := range pop.Packages {
		if _, ok := model.ParseEcosystem(eco); !ok {
			add("popular.json: ecosistema desconocido %q", eco)
		}
		seen := map[string]bool{}
		for _, n := range names {
			if n == "" || seen[n] {
				add("popular.json[%s]: nombre vacío o repetido (%q)", eco, n)
			}
			seen[n] = true
		}
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "✖", p)
		}
		return fmt.Errorf("%d problema(s) en el feed", len(problems))
	}
	fmt.Printf("✔ feed válido: %d entradas maliciosas, %d ecosistemas de nombres populares\n", len(mal.Entries), len(pop.Packages))
	return nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	dir := fs.String("dir", "db", "directorio del feed")
	keyFile := fs.String("key", "", "fichero con la clave privada (o variable de entorno DB_SIGNING_KEY)")
	_ = fs.Parse(args)
	priv := os.Getenv("DB_SIGNING_KEY")
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		priv = strings.TrimSpace(string(b))
	}
	if priv == "" {
		return fmt.Errorf("indica la clave privada con -key FICHERO o la variable DB_SIGNING_KEY")
	}
	if err := check([]string{"-dir", *dir}); err != nil {
		return err
	}
	idx, err := db.BuildIndex(*dir, time.Now())
	if err != nil {
		return err
	}
	sig, err := db.Sign(priv, idx)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "index.json"), idx, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "index.json.sig"), []byte(sig+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("✔ %s/index.json e index.json.sig regenerados\n", *dir)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("dir", "db", "directorio del feed")
	pub := fs.String("pub", "", "clave pública Ed25519 en base64 (por defecto la de db/pubkey.txt)")
	_ = fs.Parse(args)
	key := *pub
	if key == "" {
		key = db.EmbeddedPublicKey()
	}
	if key == "" {
		return fmt.Errorf("no hay clave pública: usa -pub o rellena db/pubkey.txt")
	}
	idx, err := os.ReadFile(filepath.Join(*dir, "index.json"))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(*dir, "index.json.sig"))
	if err != nil {
		return err
	}
	if err := db.Verify(key, idx, string(sig)); err != nil {
		return fmt.Errorf("firma NO válida: %w", err)
	}
	want, err := db.BuildIndex(*dir, time.Now())
	if err != nil {
		return err
	}
	var a, b struct {
		Files map[string]string `json:"files"`
	}
	_ = json.Unmarshal(idx, &a)
	_ = json.Unmarshal(want, &b)
	for name, h := range b.Files {
		if a.Files[name] != h {
			return fmt.Errorf("%s no coincide con el hash firmado en index.json (regenera y vuelve a firmar)", name)
		}
	}
	fmt.Println("✔ firma válida y hashes correctos")
	return nil
}
