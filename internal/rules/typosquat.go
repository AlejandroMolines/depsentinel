package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// Typosquat marca nombres casi idénticos a paquetes populares.
func Typosquat(c *Context, p *model.Package) []model.Finding {
	if !c.enabled("typosquat") || p.Private || p.Name == "" || strings.Contains(p.Name, "$") {
		return nil
	}
	name := model.NormalizeName(p.Ecosystem, p.Name)
	if c.Store.IsPopular(p.Ecosystem, name) || c.Store.IsBenign(p.Ecosystem, p.Name, "typosquat") {
		return nil
	}
	// Los typosquats suelen ser paquetes jóvenes y con pocas versiones: uno consolidado casi seguro es legítimo.
	if m := p.Meta; m != nil {
		if m.VersionCount >= 10 {
			return nil
		}
		if m.Created != nil && c.now().Sub(*m.Created) > 2*365*24*time.Hour {
			return nil
		}
		// Si lleva años sin tocarse y sigue en el registry, no es un typosquat activo (npm los retira).
		if m.LastRelease != nil && c.now().Sub(*m.LastRelease) > 3*365*24*time.Hour {
			return nil
		}
	}
	target, kind := Nearest(c.Store.Popular(p.Ecosystem), name)
	if target == "" {
		return nil
	}
	// El caso típico es un error al escribir una dependencia directa; en las transitivas el aviso es más débil.
	sev := model.SeverityMedium
	if !p.Direct {
		sev = model.SeverityLow
	}
	f := newFinding(p, "typosquat", "DS-TYPOSQUAT", sev, "Posible typosquatting de «"+target+"»")
	f.Detail = fmt.Sprintf("El nombre «%s» se parece mucho al paquete popular «%s» (%s). Los atacantes publican nombres casi idénticos esperando que alguien se equivoque al instalar.", p.Name, target, kind)
	f.Fix = fmt.Sprintf("Comprueba que es el paquete que querías y quién lo mantiene. Si es legítimo: depsentinel allowlist add %s --rule typosquat --reason \"...\"", p.Name)
	return []model.Finding{f}
}

// Nearest devuelve el nombre popular más parecido a name y el motivo ("" si ninguno).
func Nearest(popular []string, name string) (string, string) {
	best, bestKind, bestRank := "", "", 99
	for _, pop := range popular {
		kind, rank := similarity(pop, name)
		if kind != "" && rank < bestRank {
			best, bestKind, bestRank = pop, kind, rank
		}
	}
	return best, bestKind
}

func skeleton(s string) string {
	r := strings.NewReplacer("-", "", "_", "", ".", "")
	return r.Replace(s)
}

func similarity(pop, name string) (string, int) {
	if pop == name || len(pop) < 5 {
		return "", 0
	}
	if skeleton(pop) == skeleton(name) {
		return "solo cambian los separadores (-, _ o .)", 0
	}
	lp, ln := len(pop), len(name)
	if lp-ln > 1 || ln-lp > 1 {
		return affix(pop, name)
	}
	if !(pop[:2] == name[:2] || pop[lp-2:] == name[ln-2:]) {
		return affix(pop, name)
	}
	if osa(pop, name) == 1 {
		switch {
		case ln == lp && isTransposition(pop, name):
			return "dos letras intercambiadas", 1
		case ln == lp:
			if lp >= 6 {
				return "una letra distinta", 3
			}
		case ln > lp:
			return "una letra de más", 2
		default:
			return "una letra de menos", 2
		}
	}
	return affix(pop, name)
}

func affix(pop, name string) (string, int) {
	// Solo sufijos pegados al nombre (reactjs, lodash.js): "-js" o "-official" son habituales en paquetes legítimos.
	for _, suf := range []string{"js", ".js"} {
		if name == pop+suf {
			return "añade el sufijo «" + suf + "»", 4
		}
	}
	return "", 0
}

func isTransposition(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	if i+1 >= len(a) {
		return false
	}
	return a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
}

// osa calcula la distancia de edición con transposiciones adyacentes (optimal string alignment).
func osa(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := 0; j <= len(rb); j++ {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
