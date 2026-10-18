**Español** | [English](CONTRIBUTING.en.md)

# Contribuir a DepSentinel

¡Gracias! Las contribuciones más útiles suelen ser **informes de falsos positivos**, **paquetes maliciosos que no
detecta** y **casos de prueba reales**.

## Preparar el entorno

```bash
git clone https://github.com/AlejandroMolines/depsentinel && cd depsentinel
make check          # formato, vet, tests con -race y validación del feed
make build && ./depsentinel scan . --offline
```

Solo hace falta Go 1.22 o superior. El proyecto no tiene dependencias externas y debe seguir así: usa la biblioteca
estándar salvo que haya una razón de peso (y se discuta antes en un issue).

## Reglas de oro

1. **Una regla nueva lleva tests**: un caso que debe avisar y otro parecido que **no** debe avisar. Los falsos
   positivos cuestan más confianza que los falsos negativos.
2. **Todo hallazgo explica y propone**: título, detalle y `Fix` accionable, en español claro.
3. **Los datos externos no son de fiar**: nombres de paquete, mensajes de deprecación y respuestas de registries
   pueden venir de un atacante. Nada de ejecutarlos, interpolarlos en comandos ni pintarlos sin escapar (el panel usa
   `textContent`).
4. **Nada de red sin `--offline`**: toda consulta externa pasa por `internal/httpx` y respeta el modo sin conexión.
5. Si cambia el comportamiento visible, actualiza `docs/reglas.md` o el README.

## Añadir paquetes maliciosos a la base de datos

Edita `db/malicious.json`: `id` único (`DS-NNNN`), `ecosystem`, `name`, `versions` (`["*"]` = todas), `kind`
(`malware`, `compromised`, `sabotage` o `protestware`), `summary` y `reference` (enlace a una fuente pública: aviso
de GitHub, entrada de OSV, artículo del registry). **Sin fuente pública no se acepta.** Valida con
`go run ./cmd/dbtool check -dir db`. Los mantenedores regeneran la firma del feed (`make db-sign`).

## Añadir un ecosistema o una regla

Ver `docs/arquitectura.md`: un parser en `internal/scanner`, reglas en `internal/rules`, y tests con ficheros reales
reducidos al mínimo.

## Estilo

`gofmt` obligatorio, errores con contexto, mensajes para personas en español y identificadores (reglas, flags,
claves JSON) en inglés. Commits pequeños y descriptivos.

## Conducta

Sé amable y asume buena fe. Se acepta crítica técnica dura; no se aceptan ataques personales.
