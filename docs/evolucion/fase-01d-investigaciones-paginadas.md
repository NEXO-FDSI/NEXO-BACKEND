# Fase 1d — Todas las investigaciones de una vez, paginadas

Fecha: 2026-09-30. A pedido del usuario: un endpoint que devuelva todas las
investigaciones con paginación de máximo 10, integrado en backend y frontend.

## Backend: `GET /investigations?page=&size=`

- `size` de 1 a **10** (por defecto 10; 11 → 422), `page` ≥ 1. Orden: de la más reciente
  a la más antigua. Respuesta: `{items, page, size, total, pages}`; una página fuera de
  rango devuelve `items: []`.
- Cada item es la investigación completa, con la misma forma que `GET /indicators/{id}`:
  `indicator`, `enrichment`, `correlation`, `reports` (con `metadatos`) y `validations`.
- **Para no sobrecargar,** el `detalle` de OTX viaja recortado a lo que lee la interfaz
  (`type`, `validation` y, por pulse, `id`, `name`, `created`, `indicator_count`, `tags`,
  `malware_families`), con `detalle_completo: false`. `GET /indicators/{id}` sigue
  devolviendo el crudo completo (`detalle_completo: true`).
- **Un solo constructor en lote** (`app/reporting/investigaciones.py::construir`), usado
  por los dos endpoints: unas 5 consultas para toda la página (caché de fuentes, links de
  entidad, entidades, informes, validaciones), en vez de ~9 por investigación. Para eso,
  `get_or_fetch_enrichment` acepta la caché precargada y la correlación se separó en
  `correlation_from_link` (función pura sobre el link). Se eliminaron los tres helpers de
  repositorio que quedaron sin uso.

**Defecto encontrado por el test de consultas:** la precarga de entidades descartaba el
resultado (`list(...)`). El identity map de SQLAlchemy usa referencias débiles, así que
los objetos se liberaban y cada `link.entity` volvía a consultar: 10 investigaciones
costaban 2 consultas más que 1. Ahora las entidades se mantienen referenciadas mientras
se construye. El test se endureció primero, porque en la versión inicial no detectaba la
regresión: usaba una sola entidad y la sesión compartida de los tests ya la tenía cargada.
Ahora usa tres entidades y vacía el identity map antes de medir (mutación verificada:
falla con *9 consultas para 10 vs 7 para 1*).

## Frontend

- `sync` recorre `GET /investigations` página por página (antes: `GET /indicators` y luego
  un `GET /indicators/{id}` por cada faltante), fusiona cada investigación y depura lo que
  ya no existe. Avance: "Cargando investigaciones de la plataforma: página X de Y…".
- El OTX recortado se usa para el resumen (pulses, familias, validaciones) pero no se
  guarda como respuesta cruda: el visor JSON ofrece recargarla desde el backend.
- La lista de Investigaciones se **pagina de a 10** (Anterior / "Página X de Y · N
  investigaciones" / Siguiente). La búsqueda vuelve a la primera página.

## Medición contra Supabase real

| | Antes (Fase 1b/sync) | Ahora |
|---|---|---|
| 7 investigaciones | 1 listado + 7 × `GET /indicators/{id}` (~1,5 s c/u, de a 4) | **1 llamada, 2,1 s, 264 KB** |
| Página fuera de rango | — | 0,8 s, `items: []` |

## Verificación

- Backend: **306 tests** (6 nuevos): paginación y orden, límites (422), página vacía, cada
  item idéntico a `GET /indicators/{id}` salvo el OTX recortado y **consultas constantes**
  entre páginas de 1 y de 10.
- Frontend: lint, typecheck y build en verde; **134 tests** (cobertura de ramas 91,6 %).
  Los tests de sincronización usan páginas reales de `/investigations`; uno nuevo cubre el
  paginador (10 + 2, botones deshabilitados en los extremos, búsqueda que reinicia la página).

## Límite

Al arrancar se recorren todas las páginas, porque el Panel agrega sobre la plataforma
completa. Con miles de investigaciones convendría cargar bajo demanda y pedir los
agregados (KPIs, tácticas) al backend.
