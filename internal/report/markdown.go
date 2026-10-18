package report

import (
	"fmt"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// CommentMarker identifica el comentario de DepSentinel para poder actualizarlo en lugar de duplicarlo.
const CommentMarker = "<!-- depsentinel-report -->"

// MarkdownOptions configura el comentario de PR.
type MarkdownOptions struct {
	MaxRows   int
	ReportURL string
	FailOn    model.Severity
	Only      []model.Severity
	Min       model.Severity
}

func mdEscape(s string) string {
	s = oneLine(s)
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	if len([]rune(s)) > 170 {
		s = string([]rune(s)[:167]) + "..."
	}
	return s
}

func sevEmoji(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	}
	return "🔵"
}

// Markdown genera el comentario para el pull request.
func Markdown(rep *model.Report, o MarkdownOptions) string {
	if o.MaxRows <= 0 {
		o.MaxRows = 20
	}
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	sev, _ := model.ParseSeverity(rep.Summary.RiskLevel)
	fmt.Fprintf(&b, "## 🛡️ DepSentinel · riesgo **%s**\n\n", sev.Label())

	shown := Filter(rep.Findings, o.Min, o.Only)
	riskyPkgs := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Severity >= model.SeverityHigh {
			riskyPkgs[f.Ecosystem.Label()+"|"+f.PackageKey()] = true
		}
	}
	var eco []string
	for _, e := range rep.Ecosystems {
		eco = append(eco, e.Label())
	}
	ecoText := ""
	if len(eco) > 0 {
		ecoText = " (" + strings.Join(eco, ", ") + ")"
	}
	switch {
	case len(riskyPkgs) > 0:
		fmt.Fprintf(&b, "**%d dependencia(s) de riesgo alto o crítico** · %d paquetes analizados%s\n\n", len(riskyPkgs), rep.Summary.Packages, ecoText)
	case len(rep.Findings) == 0:
		fmt.Fprintf(&b, "✅ **Sin hallazgos** · %d paquetes analizados%s\n\n", rep.Summary.Packages, ecoText)
	default:
		fmt.Fprintf(&b, "Sin riesgos altos · %d hallazgo(s) menores · %d paquetes analizados%s\n\n", len(rep.Findings), rep.Summary.Packages, ecoText)
	}

	if len(shown) > 0 {
		b.WriteString("| Severidad | Paquete | Regla | Detalle |\n|---|---|---|---|\n")
		for i, f := range shown {
			if i >= o.MaxRows {
				break
			}
			detail := f.Title
			if f.FixedIn != "" {
				detail += " (corregido en " + f.FixedIn + ")"
			}
			fmt.Fprintf(&b, "| %s %s | `%s` | %s | %s |\n", sevEmoji(f.Severity), f.Severity.Label(), mdEscape(FormatPackage(f)), f.Rule, mdEscape(detail))
		}
		if len(shown) > o.MaxRows {
			fmt.Fprintf(&b, "\n_… y %d hallazgo(s) más en el informe completo._\n", len(shown)-o.MaxRows)
		}
		b.WriteString("\n")
		var fixes []string
		seen := map[string]bool{}
		for _, f := range shown {
			if f.Severity >= model.SeverityHigh && f.Fix != "" && !seen[f.Package+f.Fix] {
				seen[f.Package+f.Fix] = true
				fixes = append(fixes, fmt.Sprintf("- `%s`: %s", mdEscape(FormatPackage(f)), mdEscape(f.Fix)))
			}
		}
		if len(fixes) > 0 {
			if len(fixes) > 10 {
				fixes = fixes[:10]
			}
			b.WriteString("<details><summary>Cómo arreglarlo</summary>\n\n" + strings.Join(fixes, "\n") + "\n\n</details>\n\n")
		}
		b.WriteString("<details><summary>¿Falso positivo? Ignorar con justificación</summary>\n\n" +
			"Añade una excepción **con motivo** y haz commit de `.depsentinel/allowlist.json`:\n\n" +
			"```bash\ndepsentinel allowlist add <paquete> --rule <regla> --reason \"por qué es seguro\"\n```\n\n" +
			"Si crees que es un error de DepSentinel, abre un issue con la plantilla «Falso positivo».\n\n</details>\n\n")
	}
	if rep.Incomplete {
		b.WriteString("> ⚠️ El análisis está incompleto: alguna fuente de datos no estuvo disponible (revisa el informe).\n\n")
	}
	if o.ReportURL != "" {
		fmt.Fprintf(&b, "[Informe completo](%s)\n\n", o.ReportURL)
	}
	if o.FailOn > model.SeverityNone {
		if n := len(Filter(rep.Findings, o.FailOn, o.Only)); n > 0 {
			fmt.Fprintf(&b, "**El check falla**: %d hallazgo(s) de severidad %s o superior.\n", n, o.FailOn.Label())
		} else {
			fmt.Fprintf(&b, "El check pasa: ningún hallazgo de severidad %s o superior.\n", o.FailOn.Label())
		}
	}
	return b.String()
}
