// Package web embebe en el binario el panel HTML (dashboard) que usa `depsentinel report --html`.
package web

import _ "embed"

// DashboardHTML es el panel de un solo fichero. Contiene un marcador donde el CLI inyecta el informe.
//
//go:embed dashboard/index.html
var DashboardHTML []byte
