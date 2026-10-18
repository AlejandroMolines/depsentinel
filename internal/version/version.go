// Package version expone la versión de la herramienta (se inyecta con -ldflags).
package version

var (
	// Version es la versión semántica de DepSentinel.
	Version = "0.1.0-dev"
	// Commit es el hash corto del commit con el que se compiló.
	Commit = "none"
	// Date es la fecha de compilación.
	Date = "unknown"
)

// Repo es la URL del repositorio (cambia "AlejandroMolines" por tu usuario real).
const Repo = "https://github.com/AlejandroMolines/depsentinel"

// UserAgent devuelve el User-Agent que usan todas las peticiones HTTP.
func UserAgent() string {
	return "depsentinel/" + Version + " (+" + Repo + ")"
}
