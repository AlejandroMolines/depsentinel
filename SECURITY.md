**Español** | [English](SECURITY.en.md)

# Política de seguridad

## Cómo informar de una vulnerabilidad

**No abras un issue público.** Usa el [aviso privado de seguridad de GitHub](https://github.com/AlejandroMolines/depsentinel/security/advisories/new)
de este repositorio. Incluye la versión (`depsentinel version`), los pasos para reproducirlo y el impacto que ves.

Objetivo: acusar recibo en 3 días y publicar la corrección y el aviso en cuanto esté lista, dándote el crédito si lo deseas.

## Qué consideramos una vulnerabilidad

* Ejecución de código o escritura de ficheros fuera de lo esperado al analizar un lockfile, Dockerfile o workflow
  manipulado (el programa lee ficheros que pueden venir de terceros).
* Fallos en la verificación de firmas o hashes del feed de la base de datos (`db update`).
* Fugas de información hacia fuera de lo documentado en la sección de privacidad del README.
* Contenido del panel HTML que permita ejecutar scripts a partir de datos de un informe (XSS).
* Problemas en la Action, el workflow de release o la cadena de publicación.

Que DepSentinel **no detecte** un paquete malicioso concreto es un error de cobertura, no una vulnerabilidad:
abre un issue normal (o un PR con la entrada en `db/malicious.json`, ver CONTRIBUTING.md).

## Cómo se protege el propio proyecto

* **Sin dependencias de terceros en Go**: solo la biblioteca estándar. No hay árbol de dependencias que vigilar.
* Binarios de cada release con `SHA256SUMS` y atestación de procedencia (ver `docs/instalacion.md` para verificarlos).
* Compilación con `-trimpath` y sin identificador de build, para facilitar builds reproducibles.
* El feed de la base de datos se firma con Ed25519; el cliente verifica la firma del índice y el hash de cada fichero.
* El panel HTML incluye una política CSP que impide cargar o enviar nada fuera del fichero.
* El CI escanea el propio repositorio con DepSentinel y Dependabot mantiene al día las acciones y la imagen base.

## Versiones soportadas

Solo la última versión menor recibe correcciones de seguridad mientras el proyecto sea 0.x.
