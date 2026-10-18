package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

func ghEscapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

func ghEscapeProp(s string) string {
	s = ghEscapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	return strings.ReplaceAll(s, ",", "%2C")
}

// GitHubAnnotations escribe comandos de workflow (::error/::warning/::notice) que GitHub muestra en el PR.
func GitHubAnnotations(w io.Writer, rep *model.Report) {
	const max = 40
	for i, f := range rep.Findings {
		if i >= max {
			fmt.Fprintf(w, "::notice title=DepSentinel::%s\n", ghEscapeData(fmt.Sprintf("… y %d hallazgo(s) más (consulta el informe completo)", len(rep.Findings)-max)))
			return
		}
		level := "notice"
		switch {
		case f.Severity >= model.SeverityHigh:
			level = "error"
		case f.Severity == model.SeverityMedium:
			level = "warning"
		}
		props := "title=" + ghEscapeProp("DepSentinel "+f.Rule)
		if f.Source != "" {
			props = "file=" + ghEscapeProp(f.Source) + "," + props
			if f.Line > 0 {
				props = fmt.Sprintf("%s,line=%d", props, f.Line)
			}
		}
		msg := fmt.Sprintf("[%s] %s: %s", f.Severity.Label(), FormatPackage(f), oneLine(f.Title))
		if f.FixedIn != "" {
			msg += " (corregido en " + f.FixedIn + ")"
		}
		fmt.Fprintf(w, "::%s %s::%s\n", level, props, ghEscapeData(msg))
	}
}
