// Package rules contiene las reglas de detección de DepSentinel.
package rules

import (
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/config"
	"github.com/AlejandroMolines/depsentinel/internal/db"
	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/osv"
)

// Context es lo que necesitan las reglas para evaluar un paquete.
type Context struct {
	Now    time.Time
	Store  *db.Store
	Config *config.Config
	// Vulns son los avisos de OSV por clave de paquete (Package.Key()).
	Vulns map[string][]*osv.Vuln
}

func (c *Context) enabled(rule string) bool { return c.Config.RuleEnabled(rule) }

func (c *Context) unmaintainedDays() int {
	if c.Config == nil {
		return 730
	}
	return c.Config.UnmaintainedDays
}

func (c *Context) minReleaseHours() int {
	if c.Config == nil {
		return 72
	}
	return c.Config.MinReleaseAgeHours
}

func (c *Context) now() time.Time {
	if c.Now.IsZero() {
		return time.Now()
	}
	return c.Now
}

func newFinding(p *model.Package, rule, id string, sev model.Severity, title string) model.Finding {
	return model.Finding{
		ID: id, Rule: rule, Severity: sev, Ecosystem: p.Ecosystem, Package: p.Name, Version: p.Version,
		Title: title, Source: p.Source, Line: p.Line,
	}
}

// Evaluate aplica todas las reglas por paquete y correlaciona las señales.
func Evaluate(c *Context, p *model.Package) []model.Finding {
	var out []model.Finding
	out = append(out, Vulnerabilities(c, p)...)
	out = append(out, KnownMalicious(c, p)...)
	out = append(out, Typosquat(c, p)...)
	out = append(out, InstallScripts(c, p)...)
	out = append(out, Maintenance(c, p)...)
	out = append(out, Provenance(c, p)...)
	out = append(out, Unpinned(c, p)...)
	out = dedupeMalicious(out)
	return correlate(out, p)
}

// dedupeMalicious deja un único aviso "malicious" por paquete (el primero, con las referencias de todos).
func dedupeMalicious(fs []model.Finding) []model.Finding {
	first := -1
	var out []model.Finding
	for _, f := range fs {
		if f.Rule != "malicious" {
			out = append(out, f)
			continue
		}
		if first < 0 {
			first = len(out)
			out = append(out, f)
			continue
		}
		m := &out[first]
		m.References = appendUnique(m.References, f.References...)
		m.Aliases = appendUnique(m.Aliases, append([]string{f.ID}, f.Aliases...)...)
		if f.Severity > m.Severity {
			m.Severity = f.Severity
		}
	}
	return out
}

func appendUnique(dst []string, vals ...string) []string {
	seen := map[string]bool{}
	for _, d := range dst {
		seen[d] = true
	}
	for _, v := range vals {
		if v != "" && !seen[v] {
			seen[v] = true
			dst = append(dst, v)
		}
	}
	return dst
}

// correlate sube la severidad cuando varias señales débiles coinciden en el mismo paquete.
func correlate(fs []model.Finding, p *model.Package) []model.Finding {
	var hasScript, hasProv, hasFresh, hasVuln, hasUnmaintained bool
	for _, f := range fs {
		switch f.Rule {
		case "vulnerability":
			hasVuln = true
		case "unmaintained":
			hasUnmaintained = true
		case "install-script", "suspicious-script":
			hasScript = true
		case "provenance":
			hasProv = true
		case "fresh-release":
			hasFresh = true
		}
	}
	// Un paquete transitivo sin mantenimiento solo importa si además tiene vulnerabilidades.
	if hasUnmaintained && !p.Direct && !hasVuln {
		kept := fs[:0]
		for _, f := range fs {
			if f.Rule != "unmaintained" {
				kept = append(kept, f)
			}
		}
		fs = kept
	}
	sdist := p.Meta != nil && p.Meta.SdistOnly
	for i := range fs {
		switch fs[i].Rule {
		case "vulnerability":
			if hasUnmaintained && fs[i].FixedIn == "" {
				fs[i].Detail = strings.TrimSpace(fs[i].Detail + " Además el paquete parece abandonado: es poco probable que publiquen una corrección.")
			}
		case "typosquat":
			var extra []string
			if hasScript {
				extra = append(extra, "ejecuta scripts al instalarse")
			}
			if sdist {
				extra = append(extra, "solo se distribuye como código fuente (ejecuta setup.py al instalar)")
			}
			if hasFresh {
				extra = append(extra, "se publicó hace muy poco")
			}
			if len(extra) > 0 {
				if fs[i].Severity < model.SeverityHigh {
					fs[i].Severity = model.SeverityHigh
				}
				fs[i].Detail += " Además " + strings.Join(extra, " y ") + "."
			}
		case "suspicious-script":
			if hasProv {
				fs[i].Severity = model.SeverityCritical
				fs[i].Detail += " Además cambió el publicador o los mantenedores hace poco: es el patrón típico de un paquete secuestrado."
			}
		}
	}
	return fs
}
