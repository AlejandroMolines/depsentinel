package rules

import (
	"fmt"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/osv"
	"github.com/AlejandroMolines/depsentinel/internal/semver"
)

func refsFor(v *osv.Vuln) []string {
	return append([]string{v.URL()}, v.ExtraReferences(3)...)
}

func compact(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n-3] + "..."
	}
	return s
}

// Vulnerabilities convierte los avisos de OSV en hallazgos (vulnerabilidades y malware).
func Vulnerabilities(c *Context, p *model.Package) []model.Finding {
	vs := c.Vulns[p.Key()]
	if len(vs) == 0 {
		return nil
	}
	osvEco := p.Ecosystem.OSV()
	var out []model.Finding
	for _, v := range osv.GroupAliases(vs) {
		if v.IsMalicious() {
			if !c.enabled("malicious") {
				continue
			}
			f := newFinding(p, "malicious", v.ID, model.SeverityCritical, "Paquete malicioso conocido: "+v.Title())
			f.Detail = "OSV (OpenSSF Malicious Packages) lo clasifica como código malicioso. No debería estar en tu árbol de dependencias."
			f.Fix = "Elimínalo, reinstala desde cero y rota todas las credenciales (tokens, claves SSH, variables de entorno del CI) que hayan estado accesibles al instalarlo."
			f.Aliases, f.References = v.Aliases, refsFor(v)
			out = append(out, f)
			continue
		}
		if !c.enabled("vulnerability") {
			continue
		}
		cmp := func(a, b string) int { return semver.CompareEco(string(p.Ecosystem), a, b) }
		fixed := v.FixedVersion(osvEco, p.Name, p.Version, cmp)
		f := newFinding(p, "vulnerability", v.ID, v.Severity(), v.Title())
		var detail []string
		if cves := v.CVEs(); len(cves) > 0 {
			detail = append(detail, "Identificadores: "+strings.Join(cves, ", ")+".")
		}
		if d := compact(v.Details, 280); d != "" && d != f.Title {
			detail = append(detail, d)
		}
		f.Detail = strings.Join(detail, " ")
		f.Aliases, f.References = v.Aliases, refsFor(v)
		if fixed != "" {
			if p.Ecosystem == model.Go && !strings.HasPrefix(fixed, "v") {
				fixed = "v" + fixed
			}
			f.FixedIn = fixed
			f.Fix = fmt.Sprintf("Actualiza a %s o superior.", fixed)
			if p.Ecosystem == model.Go {
				f.Fix = fmt.Sprintf("Ejecuta: go get %s@%s", p.Name, fixed)
			}
		} else {
			f.Fix = "No hay versión corregida publicada: valora sustituir el paquete o aplicar las mitigaciones del aviso."
		}
		out = append(out, f)
	}
	return out
}

// KnownMalicious busca el paquete en la base de datos local (semilla + feed).
func KnownMalicious(c *Context, p *model.Package) []model.Finding {
	if !c.enabled("malicious") || p.Private {
		return nil
	}
	var out []model.Finding
	for _, e := range c.Store.LookupMalicious(p.Ecosystem, p.Name, p.Version) {
		label, sev := "Paquete malicioso conocido", model.SeverityCritical
		fix := "Elimínalo, reinstala desde cero y rota las credenciales que hayan estado accesibles al instalarlo."
		switch e.Kind {
		case "compromised":
			label = "Versión comprometida conocida"
			fix = "Fija una versión anterior o posterior no afectada, reinstala desde cero y rota las credenciales accesibles durante la instalación."
		case "sabotage":
			label, sev = "Versión saboteada por su propio autor", model.SeverityHigh
			fix = "Fija una versión anterior no afectada."
		case "protestware":
			label, sev = "Protestware conocido", model.SeverityHigh
			fix = "Fija una versión anterior no afectada."
		}
		f := newFinding(p, "malicious", e.ID, sev, label+": "+e.Summary)
		f.Detail = "Coincide con la base de datos local de DepSentinel."
		f.Fix = fix
		if e.Reference != "" {
			f.References = []string{e.Reference}
		}
		out = append(out, f)
	}
	return out
}
