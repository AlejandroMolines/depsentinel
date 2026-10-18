// Package cli implementa los comandos de depsentinel.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/AlejandroMolines/depsentinel/internal/version"
)

// Códigos de salida.
const (
	ExitOK         = 0
	ExitFindings   = 1 // hay hallazgos por encima del umbral
	ExitUsage      = 2 // uso incorrecto o configuración inválida
	ExitIncomplete = 3 // análisis incompleto con --strict, o error de ejecución
)

// exitError transporta un código de salida concreto.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func usageErr(format string, args ...any) error {
	return &exitError{code: ExitUsage, msg: fmt.Sprintf(format, args...)}
}

// App agrupa las dependencias de E/S para poder probar los comandos.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

const rootHelp = `DepSentinel %s — escanea tus dependencias antes de instalar o desplegar.

Uso:
  depsentinel <comando> [opciones]

Comandos:
  init        Crea .depsentinel.json y la lista blanca en el proyecto
  scan        Escanea dependencias (npm, PyPI, Go, Docker, GitHub Actions)
  audit       Como scan, pero muestra solo las severidades pedidas (por defecto alto y crítico)
  fix         Propone o aplica arreglos (--dry-run para solo ver el plan)
  allowlist   Gestiona la lista blanca con justificación (add, list, remove)
  sbom        Genera un SBOM CycloneDX
  report      Genera el panel HTML (--html) de un escaneo o de un informe JSON
  db          Base de datos local: update, status, clean
  version     Muestra la versión

Ejemplos:
  depsentinel scan
  depsentinel scan --ci --fail-on high
  depsentinel scan --ecosystem npm --lock package-lock.json --format json --output report.json
  depsentinel allowlist add lodash --reason "revisado manualmente"
  depsentinel sbom --format cyclonedx --output sbom.json
  depsentinel report --html --open

Códigos de salida: 0 correcto · 1 hallazgos sobre el umbral · 2 uso incorrecto · 3 análisis incompleto (--strict) o error.
Usa "depsentinel <comando> -h" para ver las opciones de cada comando.
`

// Run ejecuta la CLI y devuelve el código de salida.
func Run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	app := &App{Stdout: stdout, Stderr: stderr, Stdin: stdin}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, args)
}

// Run despacha el subcomando.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(a.Stderr, rootHelp, version.Version)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprintf(a.Stdout, rootHelp, version.Version)
		return ExitOK
	case "-v", "--version", "version":
		fmt.Fprintf(a.Stdout, "depsentinel %s (commit %s, %s)\n", version.Version, version.Commit, version.Date)
		return ExitOK
	case "init":
		err = a.cmdInit(rest)
	case "scan":
		err = a.cmdScan(ctx, rest, false)
	case "audit":
		err = a.cmdScan(ctx, rest, true)
	case "fix":
		err = a.cmdFix(ctx, rest)
	case "allowlist":
		err = a.cmdAllowlist(rest)
	case "sbom":
		err = a.cmdSBOM(rest)
	case "report":
		err = a.cmdReport(ctx, rest)
	case "db":
		err = a.cmdDB(ctx, rest)
	default:
		fmt.Fprintf(a.Stderr, "Comando desconocido: %q\n\n", cmd)
		fmt.Fprintf(a.Stderr, rootHelp, version.Version)
		return ExitUsage
	}
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(a.Stderr, ee.msg)
		}
		return ee.code
	}
	fmt.Fprintf(a.Stderr, "error: %v\n", err)
	return ExitIncomplete
}

// parseInterspersed permite poner flags antes o después de los argumentos posicionales.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			// flag ya imprimió el error y la ayuda del subcomando
			return nil, &exitError{code: ExitUsage}
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		if args[0] == "--" {
			positional = append(positional, args[1:]...)
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional, nil
}

func newFlagSet(name string, out io.Writer, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet("depsentinel "+name, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() {
		fmt.Fprintf(out, "Uso: depsentinel %s %s\n\nOpciones:\n", name, usage)
		fs.PrintDefaults()
	}
	return fs
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
