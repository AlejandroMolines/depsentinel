// Package term ofrece colores ANSI y detección de terminal.
package term

import (
	"os"
	"runtime"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// IsTerminal indica si f es un terminal interactivo.
func IsTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled decide si se usan colores ANSI en f.
func ColorEnabled(f *os.File, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	if !IsTerminal(f) {
		return false
	}
	if runtime.GOOS == "windows" {
		return os.Getenv("WT_SESSION") != "" || os.Getenv("ANSICON") != "" || os.Getenv("TERM") != ""
	}
	return true
}

// Palette aplica (o no) códigos ANSI.
type Palette struct{ Enabled bool }

func (p Palette) wrap(code, s string) string {
	if !p.Enabled || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Bold pone el texto en negrita.
func (p Palette) Bold(s string) string { return p.wrap("1", s) }

// Dim atenúa el texto.
func (p Palette) Dim(s string) string { return p.wrap("2", s) }

// Red pone el texto en rojo.
func (p Palette) Red(s string) string { return p.wrap("31", s) }

// Green pone el texto en verde.
func (p Palette) Green(s string) string { return p.wrap("32", s) }

// Yellow pone el texto en amarillo.
func (p Palette) Yellow(s string) string { return p.wrap("33", s) }

// Cyan pone el texto en cian.
func (p Palette) Cyan(s string) string { return p.wrap("36", s) }

// Severity colorea según la severidad.
func (p Palette) Severity(s model.Severity, text string) string {
	switch s {
	case model.SeverityCritical:
		return p.wrap("1;31", text)
	case model.SeverityHigh:
		return p.wrap("31", text)
	case model.SeverityMedium:
		return p.wrap("33", text)
	case model.SeverityLow:
		return p.wrap("36", text)
	}
	return text
}
