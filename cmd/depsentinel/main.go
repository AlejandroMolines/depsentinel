// Command depsentinel escanea dependencias antes de instalar o desplegar.
package main

import (
	"os"

	"github.com/AlejandroMolines/depsentinel/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin))
}
