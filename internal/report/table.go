// Package report genera las salidas: tabla, JSON, Markdown (comentario de PR), HTML y SBOM.
package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/term"
)

// TableOptions configura la salida en tabla.
type TableOptions struct {
	Color       term.Palette
	MinSeverity model.Severity
	Only        []model.Severity // si no está vacío, solo estas severidades
	Width       int
	FailOn      model.Severity // para el mensaje final (SeverityNone = no se aplica)
	CI          bool
}

func terminalWidth() int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c >= 60 {
		return c
	}
	return 120
}

// FormatPackage devuelve "nombre@versión" (o solo el nombre).
func FormatPackage(f model.Finding) string {
	if f.Version == "" {
		return f.Package
	}
	if f.Ecosystem == model.Docker {
		return f.Package + ":" + f.Version
	}
	return f.Package + "@" + f.Version
}

// count escribe "1 crítico" / "2 críticos".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func pad(s string, w int) string {
	n := utf8.RuneCountInString(s)
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

func trunc(s string, w int) string {
	if w < 4 || utf8.RuneCountInString(s) <= w {
		return s
	}
	r := []rune(s)
	return string(r[:w-1]) + "…"
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// Filter aplica MinSeverity y Only a los hallazgos.
func Filter(fs []model.Finding, min model.Severity, only []model.Severity) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Severity < min {
			continue
		}
		if len(only) > 0 {
			ok := false
			for _, s := range only {
				if f.Severity == s {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// Table escribe el informe como tabla legible.
func Table(w io.Writer, rep *model.Report, o TableOptions) {
	c := o.Color
	if o.Width <= 0 {
		o.Width = terminalWidth()
	}
	fmt.Fprintf(w, "%s %s · %s\n", c.Bold("DepSentinel"), rep.Version, rep.Target)
	if len(rep.Ecosystems) > 0 {
		var eco []string
		for _, e := range rep.Ecosystems {
			eco = append(eco, e.Label())
		}
		fmt.Fprintf(w, "%s · %s · %s\n\n", strings.Join(eco, ", "), count(rep.Summary.Packages, "paquete", "paquetes"), count(len(rep.Sources), "manifiesto", "manifiestos"))
	} else {
		fmt.Fprintln(w, "No se encontraron manifiestos soportados (package-lock.json, requirements.txt, go.mod, Dockerfile, workflows de GitHub Actions…).")
		fmt.Fprintln(w)
	}

	shown := Filter(rep.Findings, o.MinSeverity, o.Only)
	if len(shown) == 0 {
		if len(rep.Findings) == 0 {
			fmt.Fprintln(w, c.Green("✔ Sin hallazgos."))
		} else {
			fmt.Fprintln(w, c.Green("✔ Sin hallazgos en las severidades seleccionadas."))
		}
	} else {
		type row struct {
			sev      model.Severity
			cells    [4]string
			findings model.Finding
		}
		rows := make([]row, 0, len(shown))
		wSev, wPkg, wRule := len("SEVERIDAD"), len("PAQUETE"), len("REGLA")
		for _, f := range shown {
			pkg := fmt.Sprintf("%s %s", f.Ecosystem, FormatPackage(f))
			detail := oneLine(f.Title)
			if f.FixedIn != "" {
				detail += " (corregido en " + f.FixedIn + ")"
			}
			r := row{sev: f.Severity, cells: [4]string{f.Severity.Label(), pkg, f.Rule, detail}, findings: f}
			rows = append(rows, r)
			wSev = max(wSev, utf8.RuneCountInString(r.cells[0]))
			wPkg = max(wPkg, utf8.RuneCountInString(pkg))
			wRule = max(wRule, utf8.RuneCountInString(f.Rule))
		}
		wPkg = min(wPkg, 46)
		detailW := o.Width - (wSev + wPkg + wRule + 6)
		if detailW < 24 {
			detailW = 24
		}
		fmt.Fprintf(w, "%s\n", c.Dim(pad("SEVERIDAD", wSev)+"  "+pad("PAQUETE", wPkg)+"  "+pad("REGLA", wRule)+"  DETALLE"))
		for _, r := range rows {
			fmt.Fprintf(w, "%s  %s  %s  %s\n",
				c.Severity(r.sev, pad(r.cells[0], wSev)),
				pad(trunc(r.cells[1], wPkg), wPkg),
				pad(r.cells[2], wRule),
				trunc(r.cells[3], detailW))
		}
		// qué hacer primero
		var fixes []string
		seen := map[string]bool{}
		for _, f := range shown {
			if f.Severity >= model.SeverityHigh && f.Fix != "" && !seen[f.Fix+f.Package] {
				seen[f.Fix+f.Package] = true
				fixes = append(fixes, fmt.Sprintf("  • %s — %s", FormatPackage(f), oneLine(f.Fix)))
			}
		}
		if len(fixes) > 0 {
			fmt.Fprintf(w, "\n%s\n", c.Bold("Qué hacer primero"))
			for i, l := range fixes {
				if i >= 8 {
					fmt.Fprintf(w, "  … y %d más (usa --format json para ver todo)\n", len(fixes)-i)
					break
				}
				fmt.Fprintln(w, trunc(l, o.Width))
			}
		}
	}

	s := rep.Summary
	fmt.Fprintf(w, "\n%s: %s · %s · %s · %s · %s",
		c.Bold("Resumen"), count(s.Packages, "paquete", "paquetes"),
		c.Severity(model.SeverityCritical, count(s.BySeverity["critical"], "crítico", "críticos")),
		c.Severity(model.SeverityHigh, count(s.BySeverity["high"], "alto", "altos")),
		c.Severity(model.SeverityMedium, count(s.BySeverity["medium"], "medio", "medios")),
		c.Severity(model.SeverityLow, count(s.BySeverity["low"], "bajo", "bajos")))
	if s.Suppressed > 0 {
		fmt.Fprintf(w, " · %d en lista blanca", s.Suppressed)
	}
	sev, _ := model.ParseSeverity(s.RiskLevel)
	fmt.Fprintf(w, "\nRiesgo global: %s\n", c.Severity(sev, strings.ToUpper(sev.Label())))
	if o.FailOn > model.SeverityNone {
		n := len(Filter(rep.Findings, o.FailOn, o.Only))
		if n > 0 {
			fmt.Fprintf(w, "%s\n", c.Severity(model.SeverityHigh, fmt.Sprintf("✖ %s de severidad %s o superior: el build falla.", count(n, "hallazgo", "hallazgos"), o.FailOn.Label())))
		} else {
			fmt.Fprintf(w, "%s\n", c.Green(fmt.Sprintf("✔ Ningún hallazgo de severidad %s o superior.", o.FailOn.Label())))
		}
	}
}

// Warnings escribe los avisos del escaneo (datos incompletos, modo offline…).
func Warnings(w io.Writer, rep *model.Report, c term.Palette) {
	if len(rep.Warnings) == 0 {
		return
	}
	seen := map[string]bool{}
	var ws []string
	for _, x := range rep.Warnings {
		if !seen[x] {
			seen[x] = true
			ws = append(ws, x)
		}
	}
	sort.Strings(ws)
	fmt.Fprintln(w)
	for _, x := range ws {
		fmt.Fprintf(w, "%s %s\n", c.Yellow("aviso:"), x)
	}
}
