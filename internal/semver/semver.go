// Package semver compara versiones de npm/Go (semver) y de PyPI (PEP 440).
package semver

import (
	"regexp"
	"strconv"
	"strings"
)

// Version es una versión semver parseada.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string
	Build               string
}

// Parse lee "v1.2.3", "1.2", "1.2.3-beta.1+build" y similares.
func Parse(s string) (Version, bool) {
	var v Version
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return v, false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		v.Build = s[i+1:]
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if pre := s[i+1:]; pre != "" {
			v.Pre = strings.Split(pre, ".")
		}
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return v, false
	}
	nums := [3]uint64{}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, false
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, true
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Compare devuelve -1, 0 o 1 siguiendo la precedencia de semver (ignora build).
func Compare(a, b Version) int {
	if c := cmpU(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpU(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpU(a.Patch, b.Patch); c != 0 {
		return c
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		x, y := a.Pre[i], b.Pre[i]
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if c := cmpU(xn, yn); c != 0 {
				return c
			}
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpU(uint64(len(a.Pre)), uint64(len(b.Pre)))
}

// IsPrerelease indica si la versión lleva sufijo de pre-release.
func (v Version) IsPrerelease() bool { return len(v.Pre) > 0 }

// CompareStrings compara dos cadenas semver; si no se pueden parsear, usa orden léxico.
func CompareStrings(a, b string) int {
	va, okA := Parse(a)
	vb, okB := Parse(b)
	if okA && okB {
		return Compare(va, vb)
	}
	return strings.Compare(a, b)
}

// PEP440 es una versión de Python parseada.
type PEP440 struct {
	Epoch   int
	Release []int
	Pre     *[2]int // [tipo (0=a,1=b,2=rc), número]
	Post    *int
	Dev     *int
	Local   string
}

var pepRe = regexp.MustCompile(`(?i)^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d+)?)?` +
	`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?` +
	`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

// ParsePEP440 parsea una versión según PEP 440.
func ParsePEP440(s string) (PEP440, bool) {
	var v PEP440
	m := pepRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return v, false
	}
	if m[1] != "" {
		v.Epoch, _ = strconv.Atoi(m[1])
	}
	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return v, false
		}
		v.Release = append(v.Release, n)
	}
	if m[3] != "" {
		kind := 0
		switch strings.ToLower(m[3]) {
		case "a", "alpha":
			kind = 0
		case "b", "beta":
			kind = 1
		default:
			kind = 2
		}
		n := 0
		if m[4] != "" {
			n, _ = strconv.Atoi(m[4])
		}
		v.Pre = &[2]int{kind, n}
	}
	switch {
	case m[5] != "":
		n, _ := strconv.Atoi(m[5])
		v.Post = &n
	case m[6] != "":
		n := 0
		if m[7] != "" {
			n, _ = strconv.Atoi(m[7])
		}
		v.Post = &n
	}
	if m[8] != "" {
		n := 0
		if m[9] != "" {
			n, _ = strconv.Atoi(m[9])
		}
		v.Dev = &n
	}
	v.Local = strings.ToLower(m[10])
	return v, true
}

func trimRelease(r []int) []int {
	for len(r) > 1 && r[len(r)-1] == 0 {
		r = r[:len(r)-1]
	}
	return r
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ComparePEP440 devuelve -1, 0 o 1 siguiendo PEP 440.
func ComparePEP440(a, b PEP440) int {
	if c := cmpInt(a.Epoch, b.Epoch); c != 0 {
		return c
	}
	ra, rb := trimRelease(a.Release), trimRelease(b.Release)
	for i := 0; i < len(ra) || i < len(rb); i++ {
		x, y := 0, 0
		if i < len(ra) {
			x = ra[i]
		}
		if i < len(rb) {
			y = rb[i]
		}
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	// pre-release: una dev sin pre ni post es anterior a cualquier pre; sin pre es posterior.
	preKey := func(v PEP440) [2]int {
		switch {
		case v.Pre == nil && v.Post == nil && v.Dev != nil:
			return [2]int{-1, 0}
		case v.Pre == nil:
			return [2]int{99, 0}
		}
		return *v.Pre
	}
	pa, pb := preKey(a), preKey(b)
	if c := cmpInt(pa[0], pb[0]); c != 0 {
		return c
	}
	if c := cmpInt(pa[1], pb[1]); c != 0 {
		return c
	}
	postKey := func(v PEP440) int {
		if v.Post == nil {
			return -1
		}
		return *v.Post
	}
	if c := cmpInt(postKey(a), postKey(b)); c != 0 {
		return c
	}
	devKey := func(v PEP440) int {
		if v.Dev == nil {
			return int(^uint(0) >> 1)
		}
		return *v.Dev
	}
	if c := cmpInt(devKey(a), devKey(b)); c != 0 {
		return c
	}
	switch {
	case a.Local == b.Local:
		return 0
	case a.Local == "":
		return -1
	case b.Local == "":
		return 1
	}
	return strings.Compare(a.Local, b.Local)
}

// ComparePyPI compara dos versiones de PyPI; si no son PEP 440 válidas usa orden léxico.
func ComparePyPI(a, b string) int {
	va, okA := ParsePEP440(a)
	vb, okB := ParsePEP440(b)
	if okA && okB {
		return ComparePEP440(va, vb)
	}
	return strings.Compare(a, b)
}

// CompareEco compara versiones del ecosistema indicado ("pypi" usa PEP 440, el resto semver).
func CompareEco(ecosystem, a, b string) int {
	if ecosystem == "pypi" {
		return ComparePyPI(a, b)
	}
	return CompareStrings(a, b)
}

var versionToken = regexp.MustCompile(`\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.\-]+)?`)

// LowerBound extrae la primera versión que aparece en un rango npm ("^4.17.15" -> "4.17.15").
func LowerBound(spec string) string {
	return versionToken.FindString(spec)
}
