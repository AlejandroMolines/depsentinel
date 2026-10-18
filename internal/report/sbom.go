package report

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// SBOMOptions configura la generación del SBOM.
type SBOMOptions struct {
	RootName    string
	RootVersion string
	Now         time.Time
	ToolVersion string
}

type bomHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type bomProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type bomExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type bomComponent struct {
	Type               string      `json:"type"`
	BOMRef             string      `json:"bom-ref"`
	Group              string      `json:"group,omitempty"`
	Name               string      `json:"name"`
	Version            string      `json:"version,omitempty"`
	Scope              string      `json:"scope,omitempty"`
	Hashes             []bomHash   `json:"hashes,omitempty"`
	PURL               string      `json:"purl,omitempty"`
	ExternalReferences []bomExtRef `json:"externalReferences,omitempty"`
	Properties         []bomProp   `json:"properties,omitempty"`
}

type bomDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type bomTool struct {
	Type    string `json:"type"`
	Author  string `json:"author"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type bom struct {
	Schema       string `json:"$schema"`
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []bomTool `json:"components"`
		} `json:"tools"`
		Component bomComponent `json:"component"`
	} `json:"metadata"`
	Components   []bomComponent  `json:"components"`
	Dependencies []bomDependency `json:"dependencies"`
}

func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_', c == '~', c == ':':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func purlPath(s string) string {
	parts := strings.Split(s, "/")
	for i := range parts {
		parts[i] = purlEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// PURL construye el Package URL de un paquete.
func PURL(p *model.Package) string {
	v := ""
	if p.Version != "" {
		v = "@" + purlEscape(p.Version)
	}
	switch p.Ecosystem {
	case model.NPM:
		return "pkg:npm/" + purlPath(p.Name) + v
	case model.PyPI:
		return "pkg:pypi/" + purlEscape(model.NormalizeName(model.PyPI, p.Name)) + v
	case model.Go:
		return "pkg:golang/" + purlPath(p.Name) + v
	case model.Docker:
		return "pkg:docker/" + purlPath(p.Name) + v
	case model.Actions:
		return "pkg:githubactions/" + purlPath(p.Name) + v
	}
	return ""
}

func hashesFrom(integrity string) []bomHash {
	var out []bomHash
	for _, tok := range strings.Fields(integrity) {
		// Solo se emiten hashes con la longitud correcta del algoritmo, para que el SBOM sea siempre válido
		// aunque el lockfile traiga un valor corrupto.
		algs := map[string]struct {
			name string
			size int
		}{"sha512-": {"SHA-512", 64}, "sha384-": {"SHA-384", 48}, "sha256-": {"SHA-256", 32}, "sha1-": {"SHA-1", 20}}
		done := false
		for pre, alg := range algs {
			if strings.HasPrefix(tok, pre) {
				if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tok, pre)); err == nil && len(raw) == alg.size {
					out = append(out, bomHash{Alg: alg.name, Content: hex.EncodeToString(raw)})
				}
				done = true
				break
			}
		}
		if !done && strings.HasPrefix(tok, "sha256:") {
			h := strings.TrimPrefix(tok, "sha256:")
			if _, err := hex.DecodeString(h); err == nil && len(h) == 64 {
				out = append(out, bomHash{Alg: "SHA-256", Content: h})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alg < out[j].Alg })
	return out
}

func uuidV4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// CycloneDX genera un SBOM CycloneDX 1.5 en JSON.
func CycloneDX(pkgs []*model.Package, o SBOMOptions) ([]byte, error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	var doc bom
	doc.Schema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
	doc.BOMFormat = "CycloneDX"
	doc.SpecVersion = "1.5"
	doc.SerialNumber = "urn:uuid:" + uuidV4()
	doc.Version = 1
	doc.Metadata.Timestamp = now.UTC().Format(time.RFC3339)
	doc.Metadata.Tools.Components = []bomTool{{Type: "application", Author: "DepSentinel contributors", Name: "depsentinel", Version: o.ToolVersion}}
	rootName := o.RootName
	if rootName == "" {
		rootName = "proyecto"
	}
	const rootRef = "depsentinel:root"
	doc.Metadata.Component = bomComponent{Type: "application", BOMRef: rootRef, Name: rootName, Version: o.RootVersion}

	refs := map[string]string{} // Package.Key() -> bom-ref
	used := map[string]bool{rootRef: true}
	doc.Components = make([]bomComponent, 0, len(pkgs))
	for _, p := range pkgs {
		purl := PURL(p)
		ref := purl
		if ref == "" || used[ref] {
			ref = fmt.Sprintf("%s#%d", p.Key(), len(used))
		}
		used[ref] = true
		refs[p.Key()] = ref
		c := bomComponent{Type: "library", BOMRef: ref, Name: p.Name, Version: p.Version, PURL: purl, Hashes: hashesFrom(p.Integrity)}
		switch p.Ecosystem {
		case model.Docker:
			c.Type = "container"
		case model.Actions:
			c.Type = "application"
		}
		if p.Ecosystem == model.NPM && strings.HasPrefix(p.Name, "@") {
			if i := strings.Index(p.Name, "/"); i > 0 {
				c.Group, c.Name = p.Name[:i], p.Name[i+1:]
			}
		}
		if p.Ecosystem == model.Go || p.Ecosystem == model.Docker || p.Ecosystem == model.Actions || p.Ecosystem == model.PyPI || p.Ecosystem == model.NPM {
			c.Scope = "required"
		}
		if p.Dev || p.Optional {
			c.Scope = "optional"
		}
		if p.Dev && p.Ecosystem == model.NPM {
			c.Properties = append(c.Properties, bomProp{Name: "cdx:npm:package:development", Value: "true"})
		}
		if strings.HasPrefix(p.Resolved, "https://") || strings.HasPrefix(p.Resolved, "http://") {
			c.ExternalReferences = append(c.ExternalReferences, bomExtRef{Type: "distribution", URL: p.Resolved})
		}
		doc.Components = append(doc.Components, c)
	}

	rootDeps := []string{}
	for _, p := range pkgs {
		if p.Direct {
			rootDeps = append(rootDeps, refs[p.Key()])
		}
	}
	sort.Strings(rootDeps)
	doc.Dependencies = append(doc.Dependencies, bomDependency{Ref: rootRef, DependsOn: rootDeps})
	for _, p := range pkgs {
		deps := []string{}
		for _, k := range p.DependsOn {
			if r, ok := refs[k]; ok {
				deps = append(deps, r)
			}
		}
		sort.Strings(deps)
		doc.Dependencies = append(doc.Dependencies, bomDependency{Ref: refs[p.Key()], DependsOn: deps})
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
