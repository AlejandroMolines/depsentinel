package scanner

import (
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// ImageRef es una referencia de imagen descompuesta.
type ImageRef struct {
	Raw     string
	Name    string
	Tag     string
	Digest  string
	Dynamic bool
}

// ParseImageRef separa nombre, tag y digest de una referencia de imagen.
func ParseImageRef(raw string) ImageRef {
	r := ImageRef{Raw: raw, Dynamic: strings.Contains(raw, "$")}
	s := raw
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest = s[i+1:]
		s = s[:i]
	}
	slash := strings.LastIndex(s, "/")
	if c := strings.LastIndex(s, ":"); c > slash {
		r.Tag = s[c+1:]
		s = s[:c]
	}
	r.Name = s
	return r
}

var (
	remoteExecRe = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|ash|dash|python3?|perl|ruby|node)\b`)
	secretKeyRe  = regexp.MustCompile(`(?i)(passw(or)?d|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)`)
	composeImgRe = regexp.MustCompile(`^\s*(?:-\s*)?image:\s*["']?([^\s"'#]+)`)
)

type dockerStage struct {
	pkg     *model.Package
	user    string
	hasUser bool
	line    int
}

func dockerPackage(ref ImageRef, rel string, line int) *model.Package {
	version := ref.Tag
	if version == "" {
		version = "latest"
	}
	p := &model.Package{
		Ecosystem: model.Docker, Name: model.NormalizeName(model.Docker, ref.Name), Version: version,
		Source: rel, Line: line, Direct: true, Integrity: ref.Digest,
	}
	if ref.Dynamic {
		p.Private = true
	}
	return p
}

// imageFindings genera los avisos de versión fija y digest de una imagen.
func imageFindings(p *model.Package, ref ImageRef, rel string, line int) []model.Finding {
	if ref.Dynamic {
		return nil
	}
	var out []model.Finding
	if ref.Digest == "" && (ref.Tag == "" || ref.Tag == "latest") {
		out = append(out, staticFinding(model.Docker, p.Name, p.Version, rel, line, "image-tag", "DS-DOCKER-LATEST", model.SeverityMedium,
			"Imagen sin versión fija (latest)",
			"Cada build puede descargar una imagen distinta: no hay reproducibilidad y un cambio malicioso llegaría sin avisar.",
			"Fija una versión concreta y, mejor, el digest: FROM "+ref.Name+":<versión>@sha256:<digest>"))
	} else if ref.Digest == "" {
		out = append(out, staticFinding(model.Docker, p.Name, p.Version, rel, line, "image-digest", "DS-DOCKER-NODIGEST", model.SeverityLow,
			"Imagen sin digest fijado",
			"Los tags son mutables: quien controle el repositorio puede cambiar el contenido de "+ref.Name+":"+ref.Tag+".",
			"Añade el digest: FROM "+ref.Name+":"+ref.Tag+"@sha256:<digest>"))
	}
	return out
}

func splitInstruction(line string) (string, string) {
	line = strings.TrimSpace(line)
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(line[i+1:])
}

func envPairs(args string) [][2]string {
	var out [][2]string
	if !strings.Contains(args, "=") {
		f := strings.Fields(args)
		if len(f) >= 2 {
			out = append(out, [2]string{f[0], strings.Join(f[1:], " ")})
		}
		return out
	}
	for _, tok := range strings.Fields(args) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			out = append(out, [2]string{k, strings.Trim(v, `"'`)})
		}
	}
	return out
}

// ParseDockerfile analiza un Dockerfile/Containerfile.
func ParseDockerfile(abs, rel string) (*Result, error) {
	lines, err := readLogicalLines(abs)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	named := map[string]*model.Package{}
	var stages []*dockerStage
	var cur *dockerStage
	fallback := path.Base(rel)
	owner := func() (string, string) {
		if cur != nil && cur.pkg != nil {
			return cur.pkg.Name, cur.pkg.Version
		}
		return fallback, ""
	}
	for _, ll := range lines {
		text := strings.TrimSpace(ll.text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		instr, args := splitInstruction(text)
		switch strings.ToUpper(instr) {
		case "FROM":
			toks := strings.Fields(args)
			var clean []string
			for _, t := range toks {
				if !strings.HasPrefix(t, "--") {
					clean = append(clean, t)
				}
			}
			cur = &dockerStage{line: ll.no}
			stages = append(stages, cur)
			if len(clean) == 0 {
				continue
			}
			image := clean[0]
			stageName := ""
			if len(clean) >= 3 && strings.EqualFold(clean[1], "as") {
				stageName = strings.ToLower(clean[2])
			}
			switch {
			case strings.EqualFold(image, "scratch"):
			case named[strings.ToLower(image)] != nil:
				cur.pkg = named[strings.ToLower(image)]
			default:
				ref := ParseImageRef(image)
				p := dockerPackage(ref, rel, ll.no)
				cur.pkg = p
				res.Packages = append(res.Packages, p)
				res.Findings = append(res.Findings, imageFindings(p, ref, rel, ll.no)...)
			}
			if stageName != "" && cur.pkg != nil {
				named[stageName] = cur.pkg
			}
		case "RUN":
			if remoteExecRe.MatchString(args) {
				n, v := owner()
				res.Findings = append(res.Findings, staticFinding(model.Docker, n, v, rel, ll.no, "remote-script", "DS-DOCKER-CURL-PIPE", model.SeverityHigh,
					"Se descarga y ejecuta un script remoto durante el build",
					"curl|sh ejecuta lo que sirva el servidor en ese momento, sin verificar su contenido: shell> "+shorten(args, 100),
					"Descarga el fichero, verifica su hash (sha256sum -c) y ejecútalo después."))
			}
		case "ADD":
			a := args
			for strings.HasPrefix(a, "--") {
				_, a = splitInstruction(a)
			}
			if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
				n, v := owner()
				res.Findings = append(res.Findings, staticFinding(model.Docker, n, v, rel, ll.no, "remote-add", "DS-DOCKER-ADD-URL", model.SeverityMedium,
					"ADD descarga un fichero remoto sin verificarlo",
					"ADD con URL no comprueba hash ni firma: "+shorten(a, 100),
					"Usa curl/wget y verifica el sha256, o copia el fichero ya verificado con COPY."))
			}
		case "ENV", "ARG":
			for _, kv := range envPairs(args) {
				if secretKeyRe.MatchString(kv[0]) && kv[1] != "" && !strings.HasPrefix(kv[1], "$") {
					n, v := owner()
					res.Findings = append(res.Findings, staticFinding(model.Docker, n, v, rel, ll.no, "secret-in-image", "DS-DOCKER-SECRET", model.SeverityHigh,
						"Posible secreto incrustado en la imagen ("+strings.ToUpper(instr)+" "+kv[0]+")",
						"Los valores de ENV/ARG quedan en las capas y en `docker history`: cualquiera con la imagen puede leerlos.",
						"Pasa el secreto en tiempo de ejecución (variable de entorno, secreto del orquestador) o usa RUN --mount=type=secret."))
				}
			}
		case "USER":
			if cur != nil {
				cur.hasUser = true
				cur.user = strings.ToLower(strings.Fields(args + " x")[0])
			}
		}
	}
	if len(stages) > 0 {
		last := stages[len(stages)-1]
		if last.pkg != nil && (!last.hasUser || last.user == "root" || last.user == "0") {
			res.Findings = append(res.Findings, staticFinding(model.Docker, last.pkg.Name, last.pkg.Version, rel, last.line, "root-user", "DS-DOCKER-ROOT", model.SeverityLow,
				"El contenedor se ejecuta como root",
				"Si alguien explota la aplicación, tendrá privilegios de root dentro del contenedor.",
				"Añade una instrucción USER con un usuario sin privilegios."))
		}
	}
	return res, nil
}

// ParseCompose analiza docker-compose.yml / compose.yml (solo las claves image:).
func ParseCompose(abs, rel string) (*Result, error) {
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	for i, line := range strings.Split(string(data), "\n") {
		m := composeImgRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		ref := ParseImageRef(m[1])
		p := dockerPackage(ref, rel, i+1)
		res.Packages = append(res.Packages, p)
		res.Findings = append(res.Findings, imageFindings(p, ref, rel, i+1)...)
	}
	return res, nil
}
