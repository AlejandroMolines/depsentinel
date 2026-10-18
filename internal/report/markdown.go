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
	fmt.Fprintf(&b, "## 🛡️ DepSentinel · risk **%s**\n\n", sev.Label())

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
		fmt.Fprintf(&b, "**%d high or critical dependency finding(s)** · %d packages analyzed%s\n\n", len(riskyPkgs), rep.Summary.Packages, ecoText)
	case len(rep.Findings) == 0:
		fmt.Fprintf(&b, "✅ **No findings** · %d packages analyzed%s\n\n", rep.Summary.Packages, ecoText)
	default:
		fmt.Fprintf(&b, "No high risks · %d minor finding(s) · %d packages analyzed%s\n\n", len(rep.Findings), rep.Summary.Packages, ecoText)
	}

	if len(shown) > 0 {
		b.WriteString("| Severity | Package | Rule | Detail |\n|---|---|---|---|\n")
		for i, f := range shown {
			if i >= o.MaxRows {
				break
			}
			detail := f.Title
			if f.FixedIn != "" {
				detail += " (fixed in " + f.FixedIn + ")"
			}
			fmt.Fprintf(&b, "| %s %s | `%s` | %s | %s |\n", sevEmoji(f.Severity), f.Severity.Label(), mdEscape(FormatPackage(f)), f.Rule, mdEscape(detail))
		}
		if len(shown) > o.MaxRows {
			fmt.Fprintf(&b, "\n_… and %d more finding(s) in the full report._\n", len(shown)-o.MaxRows)
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
			b.WriteString("<details><summary>How to fix</summary>\n\n" + strings.Join(fixes, "\n") + "\n\n</details>\n\n")
		}
		b.WriteString("<details><summary>False positive? Ignore with justification</summary>\n\n" +
			"Add an exception **with a reason** and commit `.depsentinel/allowlist.json`:\n\n" +
			"```bash\ndepsentinel allowlist add <package> --rule <rule> --reason \"why it is safe\"\n```\n\n" +
			"If you think it is a DepSentinel bug, open an issue with the «False positive» template.\n\n</details>\n\n")
	}
	if rep.Incomplete {
		b.WriteString("> ⚠️ The analysis is incomplete: a data source was unavailable (check the report).\n\n")
	}
	if o.ReportURL != "" {
		fmt.Fprintf(&b, "[Full report](%s)\n\n", o.ReportURL)
	}
	if o.FailOn > model.SeverityNone {
		if n := len(Filter(rep.Findings, o.FailOn, o.Only)); n > 0 {
			fmt.Fprintf(&b, "**The check fails**: %d finding(s) of severity %s or higher.\n", n, o.FailOn.Label())
		} else {
			fmt.Fprintf(&b, "The check passes: no findings of severity %s or higher.\n", o.FailOn.Label())
		}
	}
	return b.String()
}
