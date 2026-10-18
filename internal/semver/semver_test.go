package semver

import "testing"

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1},
		{"v1.10.0", "v1.9.0", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-rc.1", "1.0.0-beta.11", 1},
		{"2.0.0+build.5", "2.0.0", 0},
		{"1.2", "1.2.0", 0},
		{"v0.0.0-20210101010101-abcdef123456", "v0.0.1", -1},
	}
	for _, c := range cases {
		if got := CompareStrings(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, quiero %d", c.a, c.b, got, c.want)
		}
	}
}

func TestComparePEP440(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.0", 0},
		{"1.0rc1", "1.0", -1},
		{"1.0.post1", "1.0", 1},
		{"1.0.dev1", "1.0a1", -1},
		{"2.31.0", "2.4.0", 1},
		{"1!1.0", "2.0", 1},
		{"1.0+local", "1.0", 1},
		{"1.0a2", "1.0b1", -1},
		{"1.0.post1.dev1", "1.0.post1", -1},
	}
	for _, c := range cases {
		if got := ComparePyPI(c.a, c.b); got != c.want {
			t.Errorf("ComparePyPI(%q,%q) = %d, quiero %d", c.a, c.b, got, c.want)
		}
	}
	if _, ok := ParsePEP440("no-es-version"); ok {
		t.Error("una cadena no válida no debería parsearse")
	}
}

func TestLowerBound(t *testing.T) {
	for in, want := range map[string]string{"^4.17.15": "4.17.15", "~1.2": "1.2", ">=2.0.0 <3": "2.0.0", "*": "", "1.x": "1"} {
		if got := LowerBound(in); got != want {
			t.Errorf("LowerBound(%q) = %q, quiero %q", in, got, want)
		}
	}
}

func TestCompareEco(t *testing.T) {
	if CompareEco("pypi", "1.0.post1", "1.0") != 1 || CompareEco("npm", "1.0.0-rc.1", "1.0.0") != -1 {
		t.Error("CompareEco no elige el comparador correcto")
	}
}
