package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

type goReplace struct {
	target string
	local  bool
	line   int
}

// ParseGoMod lee go.mod (require, replace) sin necesitar la toolchain de Go.
func ParseGoMod(abs, rel string) (*Result, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	replaced := map[string]goReplace{}
	block := ""
	for i, raw := range strings.Split(string(data), "\n") {
		no := i + 1
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		indirect := strings.Contains(line, "// indirect")
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if line == ")" {
			block = ""
			continue
		}
		if strings.HasSuffix(line, "(") {
			block = strings.TrimSpace(strings.TrimSuffix(line, "("))
			continue
		}
		directive, rest := block, line
		if block == "" {
			f := strings.Fields(line)
			directive = f[0]
			rest = strings.TrimSpace(strings.TrimPrefix(line, f[0]))
		}
		switch directive {
		case "module":
			res.RootName = strings.Trim(rest, `"`)
		case "require":
			f := strings.Fields(rest)
			if len(f) < 2 {
				continue
			}
			res.Packages = append(res.Packages, &model.Package{
				Ecosystem: model.Go, Name: strings.Trim(f[0], `"`), Version: f[1], Source: rel, Line: no, Direct: !indirect,
			})
		case "replace":
			parts := strings.SplitN(rest, "=>", 2)
			if len(parts) != 2 {
				continue
			}
			left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
			if len(left) == 0 || len(right) == 0 {
				continue
			}
			target := strings.Trim(right[0], `"`)
			local := strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") ||
				filepath.IsAbs(target) || (len(target) > 1 && target[1] == ':')
			replaced[strings.Trim(left[0], `"`)] = goReplace{target: target, local: local, line: no}
		}
	}
	for _, p := range res.Packages {
		r, ok := replaced[p.Name]
		if !ok {
			continue
		}
		p.Private = true
		if !r.local {
			res.Findings = append(res.Findings, staticFinding(model.Go, p.Name, p.Version, rel, r.line, "source", "DS-GO-REPLACE", model.SeverityMedium,
				"Un replace redirige el módulo a otro origen",
				fmt.Sprintf("go.mod sustituye %s por %s: el código que se compila no es el del módulo original.", p.Name, shorten(r.target, 80)),
				"Comprueba que el módulo de destino es de confianza y fija una versión concreta."))
		}
	}
	return res, nil
}
