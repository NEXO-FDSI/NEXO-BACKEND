# Fase 7a — Lotes: modelo, ingesta en bloque y consulta

Fecha: 2026-10-10. Primera fase del plan de la Fase 7
(`fase-07-campanas-plan.md`).

**Objetivo:** que el analista registre de una vez un conjunto de indicadores y que NEXO
lo conserve como un lote consultable.

## Decisiones aplicadas

Las preguntas abiertas del plan no se respondieron explícitamente. Por eso, esta fase aplica
las recomendaciones que la afectan:

| # | Decisión |
|---|---|
| P1 | El concepto se llama **lote**: `batches` en la BD y la API |
| P4 | Límite de **20 indicadores** por lote (`MAX_INDICADORES_LOTE`) |
| P7 | Al eliminar un indicador, su ítem del lote **se desvincula**, no se borra |
| P8 | El refang **deja de distinguir mayúsculas** |
| P10 | La migración se probó primero contra el Postgres local y, con tu aprobación, se aplicó en Supabase |

Cualquiera de estas decisiones se puede cambiar antes de la 7b.

## Qué se hizo

**Modelo y migración.** La migración `52f69d2bfdcc_batches` solo agrega tablas:

- **`batches`**: `id`, `nombre` y `timestamp`.
- **`batch_items`**: guarda todo lo que pegó el analista, en orden. Columnas:
  - `posicion` y `entrada` (tal como se pegó);
  - `tipo` (el declarado);
  - `ingesta`: `creado`, `existente`, `duplicado`, `invalido` o `eliminado`;
  - `motivo`;
  - `indicator_id`, que es NULL si el ítem no tiene indicador.

  Tiene un `UniqueConstraint(batch_id, indicator_id)` e índices en las dos FK.

**`POST /batches`.** Lo implementan `app/ingestion/lote.py` y `app/api/batches.py`.

- Cada ítem se valida por separado con `IndicatorCreate`, así que la normalización y la
  validación son las mismas que en `POST /indicators`.
- `ItemLote` es laxo a propósito: si el `tipo` falta o no existe, o si el valor no corresponde
  al tipo, el ítem queda `invalido` con su motivo y **el lote sigue**. Solo el tamaño de la
  petición da 422: de 2 a 20 ítems, `valor` de hasta 2.048 caracteres, `tipo` de hasta 16 y
  `nombre` de hasta 200.
- Un valor que ya está registrado se reutiliza (`existente`), sin 409.
- Dos entradas con el mismo valor canónico, como `evil[.]com` y `EVIL.COM`, son un solo
  indicador: la segunda queda `duplicado` y su motivo dice "mismo valor canónico que la
  posición N".
- Los indicadores nuevos quedan con `fuente = "Lote #<id>"`.
- Si ningún ítem es válido, responde 422 y no persiste nada.
- Puede pasar que otra petición registre el mismo valor entre el SELECT y el INSERT. En ese
  caso el endpoint reintenta una vez y, si vuelve a ocurrir, responde 409.

**`GET /batches/{id}`.** Devuelve los `items` en orden, incluidos los descartados y los
eliminados, y `investigaciones`: la de cada miembro, con la misma forma que
`GET /indicators/{id}` y armadas por `construir()`.

**`GET /batches`.** Lista los lotes más recientes con sus conteos de indicadores y descartados.
Las columnas de informe y decisión se agregan en la 7c, cuando exista `batch_reports`.

**Cascada.** `DELETE /indicators/{id}` desvincula los ítems antes de borrar el indicador: el
ítem queda `eliminado`, con `indicator_id` NULL. La respuesta lo cuenta en
`eliminados["batch_items"]`.

**Refang** (`normalizer.py`). Ahora no distingue mayúsculas: `HXXPS://`, `[DOT]` y `Hxxp[:]//`
se deshacen. El orden de los reemplazos (primero símbolos, luego esquemas) se conserva.

## Consultas acotadas

Se midieron con `before_cursor_execute` sobre el Postgres local. La tabla cuenta solo
sentencias de datos, sin los SAVEPOINT de los tests:

| Operación | Sentencias de datos | ¿Depende de N? |
|---|---|---|
| `POST /batches` | 4: INSERT del lote, un `SELECT … IN`, INSERT de los indicadores nuevos e INSERT de los ítems | No: `test_post_ejecuta_las_mismas_sentencias_con_2_y_con_20` |
| `GET /batches/{id}` | 6–7: lote, ítems con su indicador (`outer join`) y `construir()` | No: `test_get_ejecuta_las_mismas_sentencias_con_2_y_con_20` |
| `GET /batches` | 2 | No |

**Las dos pruebas de conteo se verificaron con mutaciones:**

- Un `flush` por indicador en la ingesta hace fallar la prueba de POST: 7 sentencias con 2
  indicadores frente a 25 con 20.
- Llamar a `construir()` una vez por miembro hace fallar la prueba de GET: 10 frente a 82.

### Costo de los pasos por indicador (criterio 8 del plan)

Se midió cuántas sentencias ejecuta cada paso contra el Postgres local:

| Paso | Sentencias | Con el RTT de Supabase (75 ms, Fase 0) |
|---|---|---|
| `/correlate`, entidad nueva | 12 | ≈ 0,9 s |
| `/correlate`, entidad que ya existe | 8 | ≈ 0,6 s |
| `/correlate`, repetido | 6 | ≈ 0,45 s |
| `/enrich` con una fuente configurada (tests) | 4 | — |
| `/enrich` con las tres fuentes | ≈ 10: 1 + 3 lecturas de caché + 3 × (INSERT + refresh) | ≈ 0,75 s más la red |

Los milisegundos son la cantidad de sentencias multiplicada por el RTT de la Fase 0: **no se
midieron contra Supabase** para no escribir en la base compartida. Confirman lo que corregía el
plan: la correlación ya no es el cuello de botella; el costo del paso lo pone la red de
`/enrich`.

## Verificación

- `pytest`: **355 pruebas en verde**, frente a 333 antes; 22 son nuevas.
  - `tests/test_lotes.py` (15): resultado por ítem; 422 y nada persistido; seis topes de la
    petición; reintento único ante una carrera y 409 si se repite; GET idéntico a
    `GET /indicators/{id}`; 404; lista; y las dos pruebas de conteo.
  - `tests/test_eliminacion.py` (+1): el ítem queda `eliminado` y el otro miembro, intacto.
  - `tests/test_normalization.py` (+3 casos × 2 pruebas): refang en mayúsculas.
- Migración, sobre una base desechable `nexo_migracion` en el Postgres de tests:
  - `alembic upgrade head` aplica las tres revisiones.
  - `alembic check` responde "No new upgrade operations detected", es decir, los modelos
    coinciden con la BD.
  - `alembic downgrade -1` quita solo las dos tablas nuevas.
  - `upgrade head` vuelve a aplicarla.
  - Al terminar, la base se borró.
- OpenAPI: Swagger muestra el tag "Batches", con `POST /batches`, `GET /batches` y
  `GET /batches/{batch_id}`.

### Criterios de aceptación

| # | Criterio | Estado |
|---|---|---|
| 1 | `pytest` en verde, con las pruebas nuevas | ✅ |
| 2 | Inválido o sin tipo → `invalido` con motivo; existente con el mismo id que `GET /indicators?tipo&valor`, sin 409; duplicados → un solo miembro | ✅ |
| 3 | 422 con 1 ítem, 21 ítems, `valor` de más de 2.048 caracteres o "todos inválidos", sin persistir nada | ✅ |
| 4 | El mismo número de sentencias con 2 y con 20 (POST y GET) | ✅ (con prueba de mutación) |
| 5 | `investigaciones[i]` igual a `GET /indicators/{id}` | ✅ |
| 6 | El DELETE de un miembro lo deja `eliminado` y `eliminados["batch_items"] = 1` | ✅ |
| 7 | `HXXPS://…[.]…` y `[DOT]` se normalizan | ✅ |
| 8 | Migración `upgrade`/`downgrade` en local; costo de `/correlate` y `/enrich` medido | ✅ (sentencias medidas; ms estimados con el RTT de la Fase 0) |

## Diferencias con el plan

- `GET /batches` todavía no trae `ultimo_informe` ni `decision`, porque dependen de
  `batch_reports` (7c).
- `batch_items.tipo` es `String(16)`, el mismo tope que `ItemLote.tipo`.
- `POST /batches` usa 4 sentencias y `GET /batches/{id}` de 6 a 7. El plan estimaba unas 5 y
  unas 10.

## Observaciones

- La tabla de endpoints del README no tenía las filas de `GET /indicators`,
  `GET /indicators/{id}`, `GET /investigations` ni `DELETE /indicators/{id}`, de fases
  anteriores. Solo se agregaron las de lotes.

## Prueba manual rápida

```bash
uvicorn app.main:app --reload --port 8000
curl -s -X POST localhost:8000/batches -H 'Content-Type: application/json' -d '{
  "nombre": "Escenario 4", "indicadores": [
    {"tipo": "hash", "valor": "2c4a910a1299cdae2a4e55988a2f102e"},
    {"tipo": "domain", "valor": "ervsystem[.]com"},
    {"tipo": "domain", "valor": "ERVSYSTEM.COM"},
    {"tipo": null, "valor": "no-es-un-ioc"}]}'
curl -s localhost:8000/batches/<id>
```

## Siguiente

**Migración en Supabase:** se aplicó el 2026-10-10 con `alembic upgrade head`. Ahora
`alembic current` responde `52f69d2bfdcc (head)`, y la inspección confirma las dos tablas, la
restricción `uq_batch_items_batch_indicator` y los dos índices.

7b: correlación entre indicadores (señales, vínculos, agrupaciones y conclusión), calculada al
vuelo en `GET /batches/{id}`.
