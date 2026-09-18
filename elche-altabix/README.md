# Plantilla — Dossier de inversores CdU de 0 a ÉXITO

Clonada de `torres-cotillas/index.html` (20 `<section>`, CSS byte-idéntico, sin
mención a "Torres/Cotillas/Murcia", `op-data` sigue siendo JSON válido). Diseño
FIJADO — no se rediseña, solo se rellena.

## Cómo clonar

1. `cp -r _plantilla-dossier operaciones-gestor/<slug-operacion>`
2. Sustituye cada `{{...}}` de `index.html` (búscalos con `{{`) por el dato real.
3. Sube las fotos reales a `assets/fotos/` (no se copió; solo logos/equipo, fijos
   de marca) y apunta cada `{{FOTO_...}}` a su ruta.
4. Sustituye `{{URL_DOC_...}}` por los enlaces reales de Drive de cada documento.
5. Redacta a mano los `<!-- {{BLOQUE: ... — redactar}} -->`.

## Categorías de marcadores `{{...}}`
- Identidad: `NOMBRE_OPERACION`, `PROVINCIA`, `AÑO`, `MODALIDAD`, `TIPO_ACTIVO_ORIGEN`, `TIPO_RESULTADO`, `NUM_UNIDADES`, `TIPO_UNIDAD_1/2`
- Mercado/activo: `PRECIO_M2_ZONA`, `COMPRAVENTAS_ANUALES`, `OFERTA_ALQUILER`, `SUPERFICIE_M2`, `PRODUCTOS_SIMILARES`, `PUNTO_INTERES_N`/`DISTANCIA_N` (+ `DESCRIPCION_*`)
- Económicos (repetidos en varias secciones + `op-data`): `COMPRA`, `INVERSION_TOTAL`, `CAPITAL_GESTOR(_PCT)`, `CAPITAL_INVERSORES(_PCT)`, `SERVICER_FIJO`, `VENTA_REALISTA/OPTIMISTA`, `BENEFICIO_*`, `RENTABILIDAD_*`, `PRECIO_SALIDA`, `RANGO_CIERRE`
- Obra: `OBRA_SEMANAS`, `NUM_CAPITULOS`, `PLAZO_MESES`, `REFORMA_EUR_M2`, `DURACION_*`, `HORIZONTE_VENTA`
- Riesgos: `RIESGO_N`, `P_X_I_N`, `MITIGACION_N` (añade filas `<tr>` según haga falta)
- Fotos: todos los `{{FOTO_...}}` — Documentos: `{{URL_DOC_...}}`, `{{URL_IMPULSO_INFORME}}`, `{{URL_PLATAFORMA_IN}}`, `{{URL_VISOR_INVERSOR}}`

## Bloques a REDACTAR a mano (buscar `{{BLOQUE:`)
`#resumen` (problema/valor), `#fase1` (riesgos cerrados + veredicto), `#proyecto`
(encaje técnico/urbanismo/jurídico), `#suministros`, `#riesgos` (intro), `#ejecucion`
(preparación/posicionamiento/validación precio), `#gantt` (estructura es un EJEMPLO
de 16 semanas/14 capítulos — ajustar capítulos, semanas, celdas `.on`, notas y fechas).

## Qué NO se tocó
`<style>` completo (byte-idéntico), `#equipo`/`#track` (reutilizables, no son datos
de la operación), `#servicio`/`#plan`/`#compromisos` (boilerplate CdU), y la nota
interna sobre el tono en el comentario de cabecera del HTML.
