package osv

import (
	"math"
	"strings"
)

// CVSS3 calcula la puntuación base de un vector CVSS v3.0/v3.1.
func CVSS3(vector string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	scopeChanged := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, false
	}
	av, ok1 := lookup(map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, m["AV"])
	ac, ok2 := lookup(map[string]float64{"L": 0.77, "H": 0.44}, m["AC"])
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok3 := lookup(prTable, m["PR"])
	ui, ok4 := lookup(map[string]float64{"N": 0.85, "R": 0.62}, m["UI"])
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok5 := lookup(cia, m["C"])
	i, ok6 := lookup(cia, m["I"])
	a, ok7 := lookup(cia, m["A"])
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	if scopeChanged {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp(math.Min(impact+exploitability, 10)), true
}

func lookup(t map[string]float64, k string) (float64, bool) {
	v, ok := t[k]
	return v, ok
}

// roundUp implementa la función Roundup de CVSS v3.1.
func roundUp(x float64) float64 {
	i := math.Round(x * 100000)
	if int64(i)%10000 == 0 {
		return i / 100000
	}
	return (math.Floor(i/10000) + 1) / 10
}
