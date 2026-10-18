package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/semver"
)

var securityWords = regexp.MustCompile(`(?i)(security|vulnerab|malicious|malware|compromis|critical|cve-)`)

func ago(d time.Duration) string {
	switch {
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutos", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d horas", int(d.Hours()))
	}
	return fmt.Sprintf("%d días", int(d.Hours()/24))
}

// Maintenance detecta paquetes abandonados, deprecados, retirados, recién publicados o inexistentes.
func Maintenance(c *Context, p *model.Package) []model.Finding {
	m := p.Meta
	if m == nil || p.Private {
		return nil
	}
	var out []model.Finding
	if m.PackageMissing {
		if c.enabled("version-anomaly") && (p.Ecosystem == model.NPM || p.Ecosystem == model.PyPI) {
			f := newFinding(p, "version-anomaly", "DS-PACKAGE-MISSING", model.SeverityHigh, "El paquete no existe en el registry público")
			f.Detail = "El registry público no conoce este nombre. Puede haberse retirado (por ejemplo por malware), ser un error de escritura, o ser un nombre interno que un atacante podría registrar (dependency confusion)."
			f.Fix = "Averigua de dónde sale antes de instalarlo; si es interno, usa un scope propio o un registry privado con el nombre reservado."
			out = append(out, f)
		}
		return out
	}
	if m.VersionMissing {
		if c.enabled("version-anomaly") && (p.Ecosystem == model.NPM || p.Ecosystem == model.PyPI) {
			f := newFinding(p, "version-anomaly", "DS-VERSION-MISSING", model.SeverityHigh, "La versión "+p.Version+" no existe en el registry público")
			f.Detail = "El paquete existe, pero esa versión no: pudo ser retirada tras detectarse un problema, o el lockfile no es el original."
			f.Fix = "Actualiza a una versión publicada y regenera el lockfile."
			out = append(out, f)
		}
	}
	if m.Deprecated != "" && c.enabled("deprecated") {
		sev := model.SeverityLow
		if securityWords.MatchString(m.Deprecated) {
			sev = model.SeverityMedium
		}
		// En dependencias transitivas solo importa si el motivo es de seguridad: no se pueden sustituir directamente.
		if p.Direct || sev >= model.SeverityMedium {
			f := newFinding(p, "deprecated", "DS-DEPRECATED", sev, "Versión deprecada por su mantenedor")
			f.Detail = "Mensaje del mantenedor: " + compact(m.Deprecated, 240)
			f.Fix = "Sigue las indicaciones del mensaje: normalmente hay un reemplazo o una versión posterior."
			out = append(out, f)
		}
	}
	if m.Yanked && c.enabled("yanked") {
		f := newFinding(p, "yanked", "DS-YANKED", model.SeverityMedium, "Versión retirada (yanked) por su mantenedor")
		f.Detail = "PyPI marca esta versión como no recomendable."
		if m.YankedReason != "" {
			f.Detail += " Motivo: " + compact(m.YankedReason, 200)
		}
		f.Fix = "Actualiza a una versión no retirada."
		out = append(out, f)
	}
	now := c.now()
	if days := c.unmaintainedDays(); days > 0 && m.LastRelease != nil && c.enabled("unmaintained") {
		if age := int(now.Sub(*m.LastRelease).Hours() / 24); age > days {
			f := newFinding(p, "unmaintained", "DS-UNMAINTAINED", model.SeverityLow, "Sin mantenimiento aparente desde "+m.LastRelease.Format("2006-01-02"))
			f.Detail = fmt.Sprintf("Hace %d días (más de %d) que no publica una versión. Si aparece una vulnerabilidad, es probable que no se corrija.", age, days)
			f.Fix = "Valora una alternativa mantenida o asume el mantenimiento (fork)."
			out = append(out, f)
		}
	}
	if hours := c.minReleaseHours(); hours > 0 && m.Published != nil && c.enabled("fresh-release") {
		if age := now.Sub(*m.Published); age >= 0 && age < time.Duration(hours)*time.Hour {
			f := newFinding(p, "fresh-release", "DS-FRESH-RELEASE", model.SeverityLow, "Versión publicada hace solo "+ago(age))
			f.Detail = fmt.Sprintf("Las versiones comprometidas suelen detectarse y retirarse en horas o días. Esta se publicó hace menos de %d horas.", hours)
			f.Fix = "Espera unos días antes de adoptar versiones recién publicadas, o fija la versión anterior."
			out = append(out, f)
		}
	}
	return out
}

func suspiciousMajor(version string) bool {
	v, ok := semver.Parse(version)
	if !ok {
		return false
	}
	return (v.Major >= 90 && v.Major < 1900) || (v.Major >= 2200 && v.Major < 20000000)
}

// Provenance detecta señales de secuestro de paquete y versiones anómalas.
func Provenance(c *Context, p *model.Package) []model.Finding {
	if p.Private || (p.Ecosystem != model.NPM && p.Ecosystem != model.PyPI) {
		return nil
	}
	var out []model.Finding
	if c.enabled("version-anomaly") && suspiciousMajor(p.Version) {
		f := newFinding(p, "version-anomaly", "DS-VERSION-HIGH", model.SeverityMedium, "Número de versión sospechosamente alto ("+p.Version+")")
		f.Detail = "Las versiones del tipo 99.x o 9999.x son típicas de ataques de dependency confusion: el atacante publica una versión enorme para que el gestor la prefiera."
		f.Fix = "Confirma que el paquete es el que esperabas y de qué registry viene."
		out = append(out, f)
	}
	m := p.Meta
	if m == nil || !m.Deep || !c.enabled("provenance") {
		return out
	}
	changed := m.Publisher != "" && m.PreviousPublisher != "" && !strings.EqualFold(m.Publisher, m.PreviousPublisher)
	newMaint := len(m.NewMaintainers) > 0
	if !changed && !newMaint {
		return out
	}
	// Solo es relevante en versiones recientes: en versiones antiguas el cambio de manos es historia.
	if m.Published == nil || c.now().Sub(*m.Published) > 180*24*time.Hour {
		return out
	}
	level := 0 // 0 bajo, 1 medio, 2 alto
	if changed && newMaint {
		level = 1
	}
	if c.now().Sub(*m.Published) < 30*24*time.Hour {
		level++
	}
	if p.HasInstallScript || m.HasInstallScript {
		level++
	}
	sev := []model.Severity{model.SeverityLow, model.SeverityMedium, model.SeverityHigh}[min(level, 2)]
	f := newFinding(p, "provenance", "DS-PROVENANCE", sev, "Cambio de publicador o de mantenedores en esta versión")
	var parts []string
	if changed {
		parts = append(parts, fmt.Sprintf("la versión %s la publicó «%s» y la anterior (%s) «%s»", p.Version, m.Publisher, m.PreviousVersion, m.PreviousPublisher))
	}
	if newMaint {
		parts = append(parts, "nuevos mantenedores respecto a la versión anterior: "+strings.Join(m.NewMaintainers, ", "))
	}
	f.Detail = strings.Join(parts, "; ") + ". Es normal en proyectos con varios mantenedores, pero también es el patrón de un paquete traspasado o secuestrado."
	f.Fix = "Revisa el historial de la versión (repositorio, changelog, firmas) antes de adoptarla."
	return append(out, f)
}

// Unpinned avisa de dependencias PyPI sin versión exacta.
func Unpinned(c *Context, p *model.Package) []model.Finding {
	if !p.Unpinned || p.Private || !c.enabled("unpinned") {
		return nil
	}
	f := newFinding(p, "unpinned", "DS-UNPINNED", model.SeverityLow, "Dependencia sin versión exacta fijada")
	f.Detail = "Sin versión exacta no se pueden consultar avisos de seguridad ni garantizar que cada instalación trae el mismo código."
	f.Fix = "Genera un fichero de bloqueo (pip-compile --generate-hashes, poetry lock o uv lock) y escanéalo."
	return []model.Finding{f}
}
