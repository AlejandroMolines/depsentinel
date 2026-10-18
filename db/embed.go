// Package dbdata embebe en el binario la base de datos semilla (JSON).
package dbdata

import _ "embed"

// Malicious es la lista semilla de paquetes comprometidos o maliciosos.
//
//go:embed malicious.json
var Malicious []byte

// Popular es la lista de nombres populares usada para detectar typosquatting.
//
//go:embed popular.json
var Popular []byte

// Allowlist son las excepciones integradas (scripts de instalación esperados).
//
//go:embed allowlist.json
var Allowlist []byte

// PublicKey es la clave pública Ed25519 (base64, con comentarios #) de los feeds oficiales.
//
//go:embed pubkey.txt
var PublicKey string
