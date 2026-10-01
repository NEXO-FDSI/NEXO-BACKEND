# Fase 1b — Consultas de solo lectura (deuda D11)

Fecha: 2026-09-30. Adelantada desde la fase 2 a pedido del usuario.

## Problema

El backend solo tenía POST. El frontend guardaba cada resultado en `localStorage`, así que:
otro navegador no veía las investigaciones; borrar el historial las ocultaba (aunque
seguían en Supabase); y registrar un indicador existente desde otro navegador daba **409
sin forma de abrirlo**.

## Cambios

**Backend** (sin migración; solo lectura sobre las tablas existentes):

| Endpoint | Qué devuelve |
|---|---|
| `GET /indicators` | Los más recientes (`limit` 1–500, por defecto 100) |
| `GET /indicators?tipo=…&valor=…` | Lista de 0 o 1: el valor se **normaliza igual que al registrar** (`googledrive[.]network` encuentra `googledrive.network`). 422 si llega `valor` sin `tipo` |
| `GET /indicators/{id}` | `indicator`, `enrichment` (misma forma que `/enrich`, desde la caché), `correlation` (misma forma que `/correlate`), `reports` (todas las versiones con `metadatos`) y `validations`. 404 si no existe |

`correlation_snapshot` (`app/correlation/service.py`) reconstruye la correlación **sin
escribir**: con link de la etapa (a), desde el link (entidad, confianza y evidencia
persistidas); sin link, de forma determinística sobre la caché de OTX ("sin asociación" si
la etapa (a) no resuelve; `null` si resolvería pero `/correlate` no se ejecutó, para no
inventar un paso que no ocurrió). Se refactorizó `correlate_indicator` para compartir
`_sin_asociacion()` y `_tecnicas_de()`.

**Frontend:**
- Abrir `#/investigaciones/{id}` de un caso que no está en el navegador lo **carga desde
  el backend** ("Cargando…", "no existe en el backend" ante un 404 o el error de red).
- **409:** primero se busca en el historial local; si no está, `GET /indicators?tipo&valor`
  y se abre la investigación.
- **Investigaciones:** nueva sección "Registradas desde otros navegadores" con lo que
  devuelve `GET /indicators` y no está en el historial local (respeta la búsqueda).
- Acción `loaded` del reducer: lo del backend manda (incluye validaciones hechas desde
  otros navegadores); la "entrada original" se conserva si el caso ya era local.

## Verificación

- Backend: **294 tests** (284 + 10 en `tests/test_consultas.py`): búsqueda por forma
  canónica, 422, orden, 404, caso recién registrado, **el GET devuelve exactamente lo que
  devolvieron los POST** (correlación, informe con metadatos, validación), "sin asociación"
  determinística, correlación no inventada, IP no pública y **el GET no escribe**: solo
  emite `SELECT` (listener de SQLAlchemy).
- Frontend: lint, typecheck y build en verde; 131 tests. Se agregaron dos casos de
  integración en `App.test.tsx`, únicamente para mantener la cobertura de ramas sobre el
  umbral del CI (había bajado a 89,8 %; queda en 91,9 %): recuperación tras 409 con lista
  remota y error de red al cargar.
- Contra Supabase real: la lista muestra los indicadores registrados en las pruebas
  manuales; la búsqueda defangeada encuentra `googledrive.network` (#42); la investigación
  de WannaCry #36 (anterior al sprint) se reconstruye en 1,5 s con entidad, 16 técnicas e
  informe. ThreatFox y VT figuran como "sin respuesta registrada": se enriqueció antes de
  que existieran, y "Reintentar fuentes" las completa.

## Límite

El caso local no se refresca solo: si alguien valida desde otro navegador, este lo ve al
reabrirlo desde la lista remota o tras borrar el historial. Refrescar al abrir sería un
cambio menor si hace falta.
