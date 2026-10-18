**Español** | [English](en/transparency.md)

# Transparencia

DepSentinel es gratuito. Las donaciones son opcionales y **nunca desbloquean funciones**.

## Reglas

1. Todas las funciones son gratuitas para todo el mundo. Donar o patrocinar no da acceso a reglas, formatos ni
   integraciones que los demás no tengan.
2. Cada mes se publica cuánto ha entrado y en qué se ha gastado (esta página y `web/landing/transparencia.html`).
3. Las empresas pueden patrocinar y aparecer como tales, pero no reciben prioridad en incidencias, cambios a medida
   ni voto sobre las reglas de detección.
4. Si sobra dinero se invierte en el proyecto: primero mantenimiento y después auditorías de seguridad independientes.
   Las decisiones de gasto se discuten en abierto (issues o discusiones del repositorio).

## Cómo actualizar las cuentas cada mes

Edita **un solo** fichero, `web/landing/transparency-data.json`: lo leen la página en castellano y la inglesa.

```json
{
  "currency": "EUR",
  "updated": "2026-12-01",
  "months": [
    {
      "month": "2026-11",
      "donations": 40,
      "sponsorships": 100,
      "costs": { "dominio": 12, "auditorias": 0, "otros": 9.5 },
      "note": "Primer patrocinio de empresa"
    }
  ]
}
```

* `month`: `AAAA-MM`. `donations` y `sponsorships`: importes recibidos. `costs`: cualquier conjunto de partidas
  (se suman). `note`: texto libre opcional.
* La página calcula los totales, el saldo de cada mes y el saldo acumulado; no hay que sumar nada a mano.
* Las páginas cargan el fichero con `fetch`: para verlas en local sirve la carpeta (`cd web/landing && python3 -m http.server`) en lugar de abrir el HTML directamente.
* Anota también el mes en la tabla de abajo para conservar el histórico en el repositorio.

## Histórico

| Mes | Donaciones | Patrocinios | Gastos | Notas |
|---|---|---|---|---|
| _Todavía no hay movimientos._ | | | | |

## Cuentas verificables

Usa una plataforma con libro público (Open Collective publica todos los movimientos) o enlaza los justificantes. Así
cualquiera puede comprobar las cifras sin fiarse de esta página.
