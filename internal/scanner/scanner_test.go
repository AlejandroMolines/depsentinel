package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func find(res *Result, name, version string) *model.Package {
	for _, p := range res.Packages {
		if p.Name == name && (version == "" || p.Version == version) {
			return p
		}
	}
	return nil
}

const lockV3 = `{
 "name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,
 "packages":{
  "":{"name":"app","version":"1.0.0","dependencies":{"a":"^1.0.0","@s/b":"^2.0.0"},"devDependencies":{"d":"^1"}},
  "node_modules/a":{"version":"1.2.0","resolved":"https://registry.npmjs.org/a/-/a-1.2.0.tgz","integrity":"sha512-AAAA","dependencies":{"c":"^3.0.0"}},
  "node_modules/@s/b":{"version":"2.0.1","resolved":"https://registry.npmjs.org/@s/b/-/b-2.0.1.tgz","integrity":"sha512-BBBB","hasInstallScript":true},
  "node_modules/c":{"version":"3.1.0","resolved":"https://registry.npmjs.org/c/-/c-3.1.0.tgz","integrity":"sha512-CCCC"},
  "node_modules/a/node_modules/c":{"version":"2.9.0","resolved":"https://registry.npmjs.org/c/-/c-2.9.0.tgz","integrity":"sha512-DDDD"},
  "node_modules/d":{"version":"1.0.0","dev":true,"resolved":"git+ssh://git@github.com/x/d.git#abc"},
  "node_modules/e":{"name":"real-e","version":"4.0.0","resolved":"https://registry.npmjs.org/real-e/-/real-e-4.0.0.tgz","integrity":"sha512-EEEE"},
  "node_modules/ws-pkg":{"resolved":"packages/ws-pkg","link":true},
  "node_modules/http-dep":{"version":"1.0.0","resolved":"http://registry.example.com/http-dep-1.0.0.tgz","integrity":"sha512-FFFF"},
  "packages/ws-pkg":{"version":"0.0.1","dependencies":{"c":"*"}}
 }
}`

func TestParseNPMLockV3(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "package-lock.json", lockV3)
	res, err := ParseNPMLock(p, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if res.RootName != "app" || res.RootVersion != "1.0.0" {
		t.Errorf("raíz: %q %q", res.RootName, res.RootVersion)
	}
	var names []string
	for _, x := range res.Packages {
		names = append(names, x.Name+"@"+x.Version)
	}
	sort.Strings(names)
	want := "@s/b@2.0.1,a@1.2.0,c@2.9.0,c@3.1.0,d@1.0.0,http-dep@1.0.0,real-e@4.0.0"
	if strings.Join(names, ",") != want {
		t.Errorf("paquetes: %v", names)
	}
	a := find(res, "a", "")
	if !a.Direct || a.Dev {
		t.Errorf("a debe ser directo y de producción: %+v", a)
	}
	if b := find(res, "@s/b", ""); !b.Direct || !b.HasInstallScript {
		t.Errorf("@s/b: %+v", b)
	}
	if d := find(res, "d", ""); !d.Dev || !d.Private || !d.Direct {
		t.Errorf("d (git, dev): %+v", d)
	}
	if c3 := find(res, "c", "3.1.0"); !c3.Direct {
		t.Error("c@3.1.0 lo pide un workspace del proyecto: es una dependencia directa")
	}
	if c2 := find(res, "c", "2.9.0"); c2.Direct {
		t.Error("c@2.9.0 está anidado dentro de a: es transitivo")
	}
	// resolución anidada: a depende de su propio c@2.9.0
	if len(a.DependsOn) != 1 || a.DependsOn[0] != "npm:c@2.9.0" {
		t.Errorf("a.DependsOn = %v", a.DependsOn)
	}
	var rules []string
	for _, f := range res.Findings {
		rules = append(rules, f.ID)
	}
	sort.Strings(rules)
	if strings.Join(rules, ",") != "DS-SOURCE-GIT,DS-SOURCE-HTTP" {
		t.Errorf("hallazgos estáticos: %v", rules)
	}
}

func TestParseNPMLockV1(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package.json", `{"name":"legacy","version":"0.1.0","dependencies":{"a":"^1","b":"^1"}}`)
	p := write(t, dir, "package-lock.json", `{"name":"legacy","lockfileVersion":1,"dependencies":{
	  "a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-xx","requires":{"b":"^2"},
	       "dependencies":{"b":{"version":"2.1.0","resolved":"https://registry.npmjs.org/b/-/b-2.1.0.tgz","integrity":"sha512-yy"}}},
	  "b":{"version":"1.0.0","resolved":"https://registry.npmjs.org/b/-/b-1.0.0.tgz","integrity":"sha512-zz","dev":true},
	  "alias":{"version":"npm:real@3.0.0","resolved":"https://registry.npmjs.org/real/-/real-3.0.0.tgz","integrity":"sha512-qq"}}}`)
	res, err := ParseNPMLock(p, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 4 {
		t.Fatalf("paquetes: %d", len(res.Packages))
	}
	a := find(res, "a", "")
	if !a.Direct || len(a.DependsOn) != 1 || a.DependsOn[0] != "npm:b@2.1.0" {
		t.Errorf("a: %+v", a)
	}
	if b2 := find(res, "b", "2.1.0"); b2.Direct {
		t.Error("b@2.1.0 está anidado: no es directo")
	}
	if b1 := find(res, "b", "1.0.0"); !b1.Direct || !b1.Dev {
		t.Errorf("b@1.0.0: %+v", b1)
	}
	if find(res, "real", "3.0.0") == nil {
		t.Error("el alias npm: debe resolverse al paquete real")
	}
}

func TestParseRequirements(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.txt", "numpy==1.21.0\n")
	p := write(t, dir, "requirements.txt", `# comentario
Django==3.2.0
requests[security]>=2.0
Flask_SQLAlchemy==2.5.1 ; python_version > "3"
pyyaml==5.3.1 \
    --hash=sha256:aaaa
-r base.txt
git+https://github.com/someone/lib.git#egg=somelib
--extra-index-url https://pypi.internal/simple
flask==1.*
`)
	res, err := ParseRequirements(p, "requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d := find(res, "django", "3.2.0"); d == nil || d.Unpinned {
		t.Errorf("django: %+v", d)
	}
	if r := find(res, "requests", ""); r == nil || !r.Unpinned {
		t.Errorf("requests debe quedar sin fijar: %+v", r)
	}
	if f := find(res, "flask-sqlalchemy", "2.5.1"); f == nil {
		t.Error("el nombre debe normalizarse (PEP 503) y el marcador ignorarse")
	}
	if y := find(res, "pyyaml", "5.3.1"); y == nil {
		t.Error("las líneas con --hash y continuación deben parsearse")
	}
	if n := find(res, "numpy", "1.21.0"); n == nil {
		t.Error("-r debe incluir el otro fichero")
	}
	if fl := find(res, "flask", ""); fl == nil || !fl.Unpinned {
		t.Errorf("flask==1.* no es una versión exacta: %+v", fl)
	}
	var ids []string
	for _, f := range res.Findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != "DS-EXTRA-INDEX,DS-SOURCE-URL" {
		t.Errorf("hallazgos: %v", ids)
	}
	if s := find(res, "somelib", ""); s == nil || !s.Private {
		t.Error("una dependencia por URL debe marcarse como privada")
	}
}

func TestParsePoetryAndUVLock(t *testing.T) {
	dir := t.TempDir()
	poetry := write(t, dir, "poetry.lock", `
[[package]]
name = "requests"
version = "2.31.0"
description = "x"
optional = false
python-versions = ">=3.7"

[package.dependencies]
urllib3 = ">=1.21"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"

[[package]]
name = "mylib"
version = "0.1.0"

[package.source]
type = "git"
url = "https://github.com/a/b"

[metadata]
lock-version = "2.0"
`)
	res, err := ParsePythonTOMLLock(poetry, "poetry.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 3 {
		t.Fatalf("poetry: %d paquetes", len(res.Packages))
	}
	if p := find(res, "pytest", ""); !p.Dev {
		t.Error("category dev -> Dev")
	}
	if p := find(res, "mylib", ""); !p.Private || len(res.Findings) != 1 {
		t.Errorf("origen git: %+v %v", p, res.Findings)
	}
	uv := write(t, dir, "uv.lock", `
version = 1
[[package]]
name = "proyecto"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "anyio" },
]

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }
`)
	res, err = ParsePythonTOMLLock(uv, "uv.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 2 || find(res, "proyecto", "") != nil {
		t.Errorf("uv: el proyecto en sí no debe aparecer: %v", len(res.Packages))
	}
}

func TestParsePipfileLock(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "Pipfile.lock", `{"_meta":{"sources":[{"url":"https://pypi.org/simple"}]},
	 "default":{"Requests":{"version":"==2.31.0"},"lib":{"git":"https://github.com/a/b","ref":"abc"}},
	 "develop":{"pytest":{"version":"==7.4.0"}}}`)
	res, err := ParsePipfileLock(p, "Pipfile.lock")
	if err != nil {
		t.Fatal(err)
	}
	if r := find(res, "requests", "2.31.0"); r == nil || r.Dev {
		t.Errorf("requests: %+v", r)
	}
	if x := find(res, "pytest", "7.4.0"); x == nil || !x.Dev {
		t.Errorf("pytest: %+v", x)
	}
	if l := find(res, "lib", ""); l == nil || !l.Private || len(res.Findings) != 1 {
		t.Errorf("lib: %+v", l)
	}
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "go.mod", `module example.com/app

go 1.22

require github.com/gin-gonic/gin v1.8.1

require (
	golang.org/x/text v0.3.7 // indirect
	github.com/local/mod v1.0.0
	github.com/remote/mod v1.0.0
)

replace github.com/local/mod => ../mod
replace github.com/remote/mod v1.0.0 => github.com/fork/mod v1.0.1
`)
	res, err := ParseGoMod(p, "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if res.RootName != "example.com/app" || len(res.Packages) != 4 {
		t.Fatalf("raíz %q, %d paquetes", res.RootName, len(res.Packages))
	}
	if g := find(res, "github.com/gin-gonic/gin", ""); !g.Direct || g.Private {
		t.Errorf("gin: %+v", g)
	}
	if x := find(res, "golang.org/x/text", ""); x.Direct {
		t.Error("// indirect debe marcar la dependencia como transitiva")
	}
	if l := find(res, "github.com/local/mod", ""); !l.Private {
		t.Error("replace local -> privado")
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "DS-GO-REPLACE" {
		t.Errorf("solo el replace remoto debe generar aviso: %v", res.Findings)
	}
}

func TestParseDockerfile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "Dockerfile", `FROM node:latest AS build
ARG API_TOKEN=abc123
ENV DB_PASSWORD=hunter2 PORT=3000
ENV SAFE_TOKEN=$FROM_ENV
RUN curl -fsSL https://example.com/i.sh | bash
ADD https://example.com/t.tgz /tmp/
FROM build AS test
FROM --platform=linux/amd64 nginx:1.25@sha256:aaaa
USER 1000
`)
	res, err := ParseDockerfile(p, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("paquetes: %d (una etapa que parte de otra no es una imagen externa)", len(res.Packages))
	}
	ids := map[string]int{}
	for _, f := range res.Findings {
		ids[f.ID]++
	}
	for id, n := range map[string]int{"DS-DOCKER-LATEST": 1, "DS-DOCKER-SECRET": 2, "DS-DOCKER-CURL-PIPE": 1, "DS-DOCKER-ADD-URL": 1} {
		if ids[id] != n {
			t.Errorf("%s: %d, quiero %d (%v)", id, ids[id], n, ids)
		}
	}
	if ids["DS-DOCKER-ROOT"] != 0 || ids["DS-DOCKER-NODIGEST"] != 0 {
		t.Errorf("la etapa final usa USER y digest: no debe haber avisos de root ni digest (%v)", ids)
	}
	ref := ParseImageRef("localhost:5000/team/app:1.2@sha256:abc")
	if ref.Name != "localhost:5000/team/app" || ref.Tag != "1.2" || ref.Digest != "sha256:abc" {
		t.Errorf("ParseImageRef: %+v", ref)
	}
}

func TestParseCompose(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "docker-compose.yml", "services:\n  web:\n    image: nginx\n  db:\n    image: \"postgres:16\"\n  app:\n    image: ${APP_IMAGE}\n")
	res, err := ParseCompose(p, "docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 3 {
		t.Fatalf("paquetes: %d", len(res.Packages))
	}
	n := 0
	for _, f := range res.Findings {
		if f.ID == "DS-DOCKER-LATEST" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("solo nginx (sin tag) debe avisar de latest: %d", n)
	}
}

const workflow = `name: CI
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v35
      - uses: some-org/some-action@main
      - uses: actions/setup-node@8f152de45cc393bb48ce5d89d36b731f54556e65
      - uses: github/codeql-action/init@v3
      - uses: ./local-action
      - run: echo "T: ${{ github.event.pull_request.title }}"
      - run: |
          echo ok
          echo "${{ github.head_ref }}"
      - name: seguro
        env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
`

func TestParseWorkflow(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, ".github/workflows/ci.yml", workflow)
	res, err := ParseWorkflow(p, ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for _, f := range res.Findings {
		ids[f.ID]++
	}
	for id, n := range map[string]int{
		"DS-ACTIONS-PWN-REQUEST": 1, "DS-ACTIONS-INJECTION": 2, "DS-ACTIONS-BRANCH": 1,
		"DS-ACTIONS-TAG": 3, "DS-ACTIONS-NO-PERMISSIONS": 1,
	} {
		if ids[id] != n {
			t.Errorf("%s: %d, quiero %d (%v)", id, ids[id], n, ids)
		}
	}
	if find(res, "actions/setup-node", "") == nil || find(res, "github/codeql-action", "v3") == nil {
		t.Error("las acciones (incluida la de subruta) deben aparecer como paquetes")
	}
	for _, f := range res.Findings {
		if f.Package == "actions/setup-node" {
			t.Error("una acción fijada a SHA no debe generar avisos")
		}
	}
}

func TestDetectAndClassify(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"package-lock.json", "web/package-lock.json", "node_modules/x/package-lock.json", "requirements/dev.txt",
		"requirements-prod.txt", "go.mod", "testdata/go.mod", "sub/Dockerfile", "docker-compose.prod.yml", ".github/workflows/a.yml",
		".github/workflows/sub/b.yml", ".github/actions/mine/action.yml", "README.md"} {
		write(t, dir, f, "x")
	}
	files, err := Detect(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[model.Ecosystem]string{
		model.NPM:     "package-lock.json,web/package-lock.json",
		model.PyPI:    "requirements-prod.txt,requirements/dev.txt",
		model.Go:      "go.mod",
		model.Docker:  "docker-compose.prod.yml,sub/Dockerfile",
		model.Actions: ".github/actions/mine/action.yml,.github/workflows/a.yml",
	}
	for eco, w := range want {
		if got := strings.Join(files[eco], ","); got != w {
			t.Errorf("%s: %q, quiero %q", eco, got, w)
		}
	}
	files, _ = Detect(dir, []string{"web"})
	if len(files[model.NPM]) != 1 {
		t.Errorf("ignore_paths debe excluir web/: %v", files[model.NPM])
	}
}
