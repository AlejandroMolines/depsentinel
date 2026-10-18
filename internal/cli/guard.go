package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// cmdGuard intercepta una instalación de dependencias: genera primero el lockfile
// sin ejecutar scripts (--ignore-scripts), escanea y solo si está limpio ejecuta
// la instalación real con scripts habilitados.
func (a *App) cmdGuard(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageErr("uso: depsentinel guard <npm|yarn|pnpm> <install|add|i> [opciones]\n       depsentinel guard -- <comando...>")
	}

	// Forma genérica: depsentinel guard -- <comando...>
	if args[0] == "--" {
		if len(args) < 2 {
			return usageErr("falta el comando tras --")
		}
		return a.runPassthrough(args[1:])
	}

	manager := args[0]
	rest := args[1:]
	switch manager {
	case "npm", "yarn", "pnpm":
	default:
		return usageErr("gestor no soportado %q (usa npm, yarn o pnpm)", manager)
	}

	isInstall := false
	for _, r := range rest {
		if r == "install" || r == "i" || r == "add" || r == "ci" {
			isInstall = true
			break
		}
	}
	if !isInstall {
		// Comando no es una instalación: se ejecuta tal cual.
		return a.runPassthrough(append([]string{manager}, rest...))
	}

	dir := "."
	for i, r := range rest {
		if r == "--prefix" && i+1 < len(rest) {
			dir = rest[i+1]
		}
	}

	// 1) Generar el lockfile sin ejecutar scripts.
	fmt.Fprintf(a.Stderr, "→ Generando lockfile con --ignore-scripts…\n")
	lockArgs := lockfileArgs(manager, rest)
	cmd := exec.Command(manager, lockArgs...)
	cmd.Dir = dir
	cmd.Stdout = a.Stdout
	cmd.Stderr = a.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("no se pudo generar el lockfile: %w", err)
	}

	// 2) Escanear.
	fmt.Fprintf(a.Stderr, "→ Escaneando dependencias…\n")
	err := a.cmdScan(ctx, []string{dir, "--ci", "--fail-on", "high"}, false)
	if err != nil {
		fmt.Fprintf(a.Stderr, "\n✖ Instalación abortada: revisa los hallazgos anteriores.\n")
		return err
	}

	// 3) Instalación real con scripts habilitados.
	fmt.Fprintf(a.Stderr, "→ Instalando (scripts habilitados)…\n")
	cmd = exec.Command(manager, rest...)
	cmd.Dir = dir
	cmd.Stdout = a.Stdout
	cmd.Stderr = a.Stderr
	cmd.Stdin = a.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("instalación fallida: %w", err)
	}
	fmt.Fprintf(a.Stderr, "✔ Instalación completada.\n")
	return nil
}

func lockfileArgs(manager string, rest []string) []string {
	// Genera solo el lockfile, sin instalar node_modules ni ejecutar scripts.
	switch manager {
	case "npm":
		return append([]string{"install", "--package-lock-only", "--ignore-scripts"}, filterPackageArgs(rest)...)
	case "pnpm":
		return append([]string{"install", "--lockfile-only", "--ignore-scripts"}, filterPackageArgs(rest)...)
	case "yarn":
		return append([]string{"install", "--mode=skip-build"}, filterPackageArgs(rest)...)
	}
	return rest
}

func filterPackageArgs(rest []string) []string {
	// Conserva los paquetes solicitados (npm install foo) y descarta flags de instalación.
	var out []string
	skipNext := false
	for _, r := range rest {
		if skipNext {
			skipNext = false
			continue
		}
		if r == "--prefix" {
			skipNext = true
			continue
		}
		if strings.HasPrefix(r, "--") {
			continue
		}
		if r == "install" || r == "i" || r == "add" || r == "ci" {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (a *App) runPassthrough(argv []string) error {
	if len(argv) == 0 {
		return usageErr("falta el comando")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = a.Stdout
	cmd.Stderr = a.Stderr
	cmd.Stdin = a.Stdin
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}