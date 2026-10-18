package rules

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/registry"
)

type scriptPattern struct {
	id     string
	re     *regexp.Regexp
	sev    model.Severity
	why    string
	strong bool // se considera indicio fiable también dentro del contenido de ficheros
}

var scriptPatterns = []scriptPattern{
	{"remote-exec", regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^\n|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`), model.SeverityCritical,
		"descarga y ejecuta código remoto (curl | sh)", true},
	{"powershell-download", regexp.MustCompile(`(?i)powershell[^\n]*(-enc\b|-encodedcommand|downloadstring|\biex\b|invoke-expression|invoke-webrequest)`), model.SeverityCritical,
		"ejecuta PowerShell codificado o descarga código remoto", true},
	{"reverse-shell", regexp.MustCompile(`(?i)(/dev/tcp/|\bnc(at)?\b[^\n]*\s-e\s|\bbash\s+-i\b|socat[^\n]*exec:|mkfifo[^\n]*\bnc\b)`), model.SeverityCritical,
		"patrón de shell inversa", true},
	{"cryptominer", regexp.MustCompile(`(?i)(xmrig|stratum\+tcp|minerd|cpuminer|coinhive|cryptonight)`), model.SeverityCritical,
		"referencias a minería de criptomonedas", true},
	{"exfil-endpoint", regexp.MustCompile(`(?i)(webhook\.site|pastebin\.com|transfer\.sh|ngrok\.(io|app)|requestbin|pipedream\.net|burpcollaborator|interact\.sh|oast\.(fun|pro|me|live|site|online)|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot)`), model.SeverityHigh,
		"contacta con un servicio típico de exfiltración de datos", true},
	{"credential-access", regexp.MustCompile(`(?i)(id_rsa|id_ed25519|\.npmrc|\.git-credentials|\.ssh/|/\.aws/|\.aws/credentials|\.kube/config|\.docker/config\.json|/etc/passwd|/etc/shadow|\bNPM_TOKEN\b|\bGITHUB_TOKEN\b|\bGH_TOKEN\b|\bAWS_SECRET_ACCESS_KEY\b|\bAWS_ACCESS_KEY_ID\b|\bSLACK_TOKEN\b)`), model.SeverityHigh,
		"accede a credenciales o ficheros sensibles", false},
	{"env-dump", regexp.MustCompile(`(?i)(\benv\b\s*\|\s*(curl|nc|base64)|printenv\s*\||JSON\.stringify\(\s*process\.env)`), model.SeverityHigh,
		"vuelca las variables de entorno", false},
	{"obfuscation", regexp.MustCompile(`(?i)(\beval\s*\(|new\s+Function\s*\(|\batob\s*\(|base64\s+(-d|--decode)|Buffer\.from\([^)]*base64|String\.fromCharCode)`), model.SeverityHigh,
		"código ofuscado o decodificado en tiempo de ejecución", false},
}

var (
	ipURLRe  = regexp.MustCompile(`https?://([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
	netUseRe = regexp.MustCompile(`(?i)(https?://|require\(['"](https?|net|dns|tls|http2)['"]\)|\bfetch\s*\(|XMLHttpRequest|\.connect\s*\()`)
)

func snippet(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

// externalIP devuelve una URL con IP pública (descarta loopback y redes privadas).
func externalIP(s string) string {
	for _, m := range ipURLRe.FindAllStringSubmatch(s, -1) {
		ip := m[1]
		switch {
		case strings.HasPrefix(ip, "127."), strings.HasPrefix(ip, "10."), strings.HasPrefix(ip, "192.168."),
			strings.HasPrefix(ip, "0."), strings.HasPrefix(ip, "169.254."):
			continue
		}
		if strings.HasPrefix(ip, "172.") {
			var second int
			fmt.Sscanf(ip, "172.%d.", &second)
			if second >= 16 && second <= 31 {
				continue
			}
		}
		return m[0]
	}
	return ""
}

// AnalyzeCommand evalúa la línea de comandos de un script de instalación.
func AnalyzeCommand(cmd string) []model.ScriptHit {
	var hits []model.ScriptHit
	for _, sp := range scriptPatterns {
		if m := sp.re.FindString(cmd); m != "" {
			hits = append(hits, model.ScriptHit{ID: sp.id, Severity: sp.sev, Why: sp.why, Match: snippet(m)})
		}
	}
	if m := externalIP(cmd); m != "" {
		hits = append(hits, model.ScriptHit{ID: "exfil-endpoint", Severity: model.SeverityHigh, Why: "contacta con una IP pública directa", Match: snippet(m)})
	}
	return hits
}

// AnalyzeContent evalúa el contenido de un fichero ejecutado al instalar.
// Es más conservador que AnalyzeCommand: las señales débiles solo suben de nivel si se combinan con uso de red.
func AnalyzeContent(text string) []model.ScriptHit {
	var hits []model.ScriptHit
	cred, obf := false, false
	for _, sp := range scriptPatterns {
		m := sp.re.FindString(text)
		if m == "" {
			continue
		}
		switch {
		case sp.strong:
			hits = append(hits, model.ScriptHit{ID: sp.id, Severity: sp.sev, Why: sp.why, Match: snippet(m)})
		case sp.id == "credential-access" || sp.id == "env-dump":
			cred = true
		case sp.id == "obfuscation":
			obf = true
		}
	}
	if m := externalIP(text); m != "" {
		hits = append(hits, model.ScriptHit{ID: "exfil-endpoint", Severity: model.SeverityHigh, Why: "contacta con una IP pública directa", Match: snippet(m)})
	}
	net := netUseRe.MatchString(text)
	switch {
	case cred && net:
		hits = append(hits, model.ScriptHit{ID: "credential-exfil", Severity: model.SeverityCritical, Why: "lee credenciales o variables de entorno y usa la red"})
	case cred:
		hits = append(hits, model.ScriptHit{ID: "credential-access", Severity: model.SeverityMedium, Why: "accede a credenciales o ficheros sensibles"})
	}
	if obf && net {
		hits = append(hits, model.ScriptHit{ID: "obfuscated-network", Severity: model.SeverityHigh, Why: "código ofuscado que además usa la red"})
	}
	return hits
}

var scriptFileRe = regexp.MustCompile(`\.(js|mjs|cjs|sh|bash|bat|cmd|ps1|py)$`)

// scriptFiles extrae los ficheros que invoca un comando ("node scripts/install.js && ./setup.sh").
func scriptFiles(cmd string) []string {
	var out []string
	for _, tok := range strings.Fields(cmd) {
		tok = strings.Trim(tok, `"';()&|`)
		if scriptFileRe.MatchString(tok) && !strings.Contains(tok, "://") && !strings.HasPrefix(tok, "-") {
			out = append(out, tok)
		}
	}
	return out
}

// ScanTarball inspecciona los ficheros que ejecutan los scripts de instalación dentro de un tarball.
func ScanTarball(files []registry.TarFile, scripts map[string]string) []model.ScriptHit {
	byPath := map[string][]byte{}
	for _, f := range files {
		byPath[path.Clean(f.Path)] = f.Data
	}
	names := make([]string, 0, len(scripts))
	for k := range scripts {
		names = append(names, k)
	}
	sort.Strings(names)
	var hits []model.ScriptHit
	seen := map[string]bool{}
	for _, script := range names {
		for _, cand := range scriptFiles(scripts[script]) {
			p := path.Clean(strings.TrimPrefix(cand, "./"))
			data, ok := byPath[p]
			if !ok || seen[p] {
				continue
			}
			seen[p] = true
			if len(data) > 2<<20 {
				data = data[:2<<20]
			}
			if bytes.IndexByte(data[:min(len(data), 8192)], 0) >= 0 {
				continue // binario
			}
			for _, h := range AnalyzeContent(string(data)) {
				h.Script, h.File = script, p
				hits = append(hits, h)
			}
		}
	}
	return hits
}

var installOrder = []string{"preinstall", "install", "postinstall"}

func maxHit(hits []model.ScriptHit) model.ScriptHit {
	best := hits[0]
	for _, h := range hits[1:] {
		if h.Severity > best.Severity {
			best = h
		}
	}
	return best
}

// InstallScripts evalúa los scripts preinstall/install/postinstall de paquetes npm.
func InstallScripts(c *Context, p *model.Package) []model.Finding {
	if p.Ecosystem != model.NPM || p.Private {
		return nil
	}
	var scripts map[string]string
	var deepHits []model.ScriptHit
	hasFlag := p.HasInstallScript
	if p.Meta != nil {
		scripts = p.Meta.InstallScripts
		deepHits = p.Meta.ScriptHits
		hasFlag = hasFlag || p.Meta.HasInstallScript
	}
	if !hasFlag && len(scripts) == 0 {
		return nil
	}
	var hits []model.ScriptHit
	for _, name := range installOrder {
		if cmd := scripts[name]; cmd != "" {
			for _, h := range AnalyzeCommand(cmd) {
				h.Script = name
				hits = append(hits, h)
			}
		}
	}
	hits = append(hits, deepHits...)

	if len(hits) > 0 {
		if !c.enabled("suspicious-script") {
			return nil
		}
		top := maxHit(hits)
		f := newFinding(p, "suspicious-script", "DS-SUSPICIOUS-SCRIPT", top.Severity, "Script de instalación sospechoso: "+top.Why)
		var lines []string
		for i, h := range hits {
			if i >= 4 {
				lines = append(lines, fmt.Sprintf("y %d indicio(s) más", len(hits)-i))
				break
			}
			where := h.Script
			if h.File != "" {
				where += " → " + h.File
			}
			line := where + ": " + h.Why
			if h.Match != "" {
				line += " («" + h.Match + "»)"
			}
			lines = append(lines, line)
		}
		f.Detail = strings.Join(lines, "; ") + "."
		f.Fix = fmt.Sprintf("No lo instales hasta revisarlo (npm view %s@%s scripts; npm pack y abre el tarball). Mientras tanto, instala con --ignore-scripts.", p.Name, p.Version)
		return []model.Finding{f}
	}

	if !c.enabled("install-script") || c.Store.IsBenign(p.Ecosystem, p.Name, "install-script") {
		return nil
	}
	f := newFinding(p, "install-script", "DS-INSTALL-SCRIPT", model.SeverityLow, "Ejecuta scripts al instalarse (preinstall/install/postinstall)")
	if len(scripts) > 0 {
		var parts []string
		for _, name := range installOrder {
			if cmd := scripts[name]; cmd != "" {
				parts = append(parts, name+": "+snippet(cmd))
			}
		}
		f.Detail = strings.Join(parts, "; ") + ". No se detectaron patrones peligrosos en el comando."
	} else {
		f.Detail = "El lockfile indica que el paquete ejecuta scripts de instalación; no se han podido inspeccionar (sin conexión)."
	}
	f.Fix = "Revisa qué hace el script. Con npm install --ignore-scripts (o ignore-scripts=true en .npmrc) no se ejecutan."
	return []model.Finding{f}
}
