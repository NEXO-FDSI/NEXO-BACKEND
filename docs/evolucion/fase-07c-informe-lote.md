# Fase 7c — Informe conjunto del lote y su validación

Fecha: 2026-10-10. Tercera y última fase de backend del plan de la Fase 7
(`fase-07-campanas-plan.md`, §2.8–§2.10).

**Objetivo:** convertir la correlación del lote (7b) en un informe conjunto auditable, con un
análisis del LLM que solo redacta, y dejar que el analista lo acepte o lo rechace con
historial. Con esto, los escenarios 3 y 4 de la propuesta pasan de **"Parcial" a "Cumple"**.

## Qué se hizo

### Persistencia

La migración `f9c2e4b21c9c_batch_reports` solo agrega tablas:

- **`batch_reports`**: `batch_id`, `contenido` (Markdown), `conclusion`, `metadatos` (JSON en
  Text) y `timestamp`. Guarda una fila por versión.
- **`batch_validation`**: `batch_report_id`, `decision`, `analista` (NULL) y `timestamp`.
  Copia la estructura de `human_validation`.

### Endpoints

- **`POST /batches/{id}/report`** genera una versión nueva del informe.
  - Trabaja solo sobre lo persistido: reutiliza la carga de `GET /batches/{id}` (`_cargar`) y
    no enriquece ni correlaciona ningún indicador.
  - Devuelve **400** si ningún miembro está enriquecido y **404** si el lote no existe.
  - Los miembros pendientes no impiden el informe: quedan declarados como cobertura parcial.
- **`POST /batch-reports/{id}/validate`** recibe `{"decision"}`, igual que la validación
  individual, y guarda cada decisión como una fila nueva. Devuelve 404 si el informe no existe
  y 422 si la decisión no es válida.
- **`GET /batches/{id}`** agrega `informes` (todas las versiones) y `validaciones`
  (historial).
- **`GET /batches`** agrega `ultimo_informe` y `decision`: la decisión vigente del último
  informe, o `null` si está pendiente. Esto quedó pendiente en la 7a.

### Informe

**El informe** lo arma `app/reporting/lote.py`, con una plantilla fija de 7 secciones:

1. Conclusión.
2. Indicadores (tabla).
3. Vínculos, con sus señales y su origen.
4. Cobertura ATT&CK conjunta por táctica, con el aviso "no prueba relación".
5. Indicadores que no participan, con el motivo, y las entradas descartadas.
6. Cobertura de fuentes y límites.
7. Análisis.

Cuando no hay relación, la sección 1 dice literalmente **"Sin relación demostrable entre los
indicadores."** y aclara que es un resultado válido. Los valores de los indicadores van como
`código` (R8 del plan): `remark-gfm` no los convierte en enlaces clicables. `metadatos` congela
`correlacion` (idéntica a la del GET), `descartados` e `ia`.

### Análisis de IA

**El análisis de IA** lo produce `generate_batch_analysis` (`ai_component/service.py`):

- **Reutilización:** usa los mismos `generate_analysis`, `parsear` y `depurar` que el informe
  individual. La parte común (llamar al modelo, validar y depurar) quedó extraída en
  `_redactar`, y el informe individual no cambió: todas sus pruebas pasan intactas.
- **Cortes:** no llama al modelo si ningún miembro resolvió entidad (invariante 5) ni si
  Chroma no devuelve texto oficial de las técnicas. Si el LLM falla, el informe se genera
  igual.
- **Contexto** (`prompt_builder.py::construir_contexto_lote`):
  - `E-LOTE`: la conclusión, las agrupaciones (con sus `E-V#`), los que no participan y la
    cobertura.
  - Un `E-I#` por indicador procesado, con el valor recortado a 100 caracteres.
  - Hasta 10 `E-V#`, los de mayor confianza; si se recortan, el prompt lo dice.
  - Hasta 6 `T####`: primero las técnicas documentadas para varias entidades, luego repartidas
    por táctica, con descripción de hasta 500 caracteres. No usa embeddings.
- **Qué no entra al prompt:** los nombres de los pulses (texto libre de terceros) ni el nombre
  del lote.
- **Citas:** como todos los bloques de evidencia empiezan con `E-`, `depurar` funciona sin
  cambios.
- **`REGLAS_LOTE`:** la agrupación la decide NEXO; solo un `E-V` sustenta una relación; nunca
  "misma campaña" ni "mismo actor"; compartir técnicas no prueba relación; una fuente sin
  verificar no es "sin evidencia".

## Consultas acotadas

| Operación | Sentencias de datos | ¿Depende de N? |
|---|---|---|
| `POST /batches/{id}/report` | 7: lote, ítems, `construir()` e INSERT del informe | No (`test_el_informe_ejecuta_las_mismas_sentencias_con_2_y_con_20`) |
| `GET /batches/{id}` | 8: lo de la 7b más informes y validaciones | No (prueba de la 7a) |
| `GET /batches` | 4: lotes, conteos y `DISTINCT ON` del último informe y su decisión | No |

## Resultados

### Datos congelados (pytest, `test_e2e_scenarios.py`)

- **Escenario 3, antes "Parcial":** un informe conjunto con "Sin relación demostrable entre
  los indicadores.", la cobertura agrupada por táctica en orden ATT&CK (15 secciones `###`,
  de Reconnaissance a Impact), cada entidad en la tabla y **una sola** llamada al LLM, con
  `E-LOTE` y `E-I1…E-I3` y ningún `E-V`.
- **Escenario 4, antes "Parcial":** una agrupación explícita, `A1 = {I1, I2}`, sustentada por
  "4 pulse(s) enfocado(s)" de OTX. El informe trae las 36 técnicas comunes y la aclaración
  "no prueba que pertenezcan a la misma campaña".

### En vivo

Se corrió con OTX, ThreatFox, VirusTotal y **Groq** (`qwen/qwen3.8-27b`) reales, contra una
base local desechable (no Supabase):

| Caso | Conclusión | IA | Qué redactó el modelo |
|---|---|---|---|
| M1 (escenario 4) | relación demostrable, A1 de confianza media | generado en 1,5 s; prompt de 7.034 caracteres (1.938 tokens); respuesta de 482 tokens; **0 descartes** | "relación demostrable entre I1 e I2 vía vínculo E-V1… La coincidencia de técnicas no prueba misma campaña". Todos sus hallazgos citan `E-V1`, `E-LOTE` o `E-I#` |
| M2 (escenario 3) | sin relación demostrable; cobertura parcial (VirusTotal agotó su cupo con I3) | generado en 3,2 s; prompt de 6.753 caracteres (1.752 tokens); respuesta de 599 tokens; **0 descartes** | "NEXO no detecta relación demostrable entre los tres indicadores… VirusTotal no validó el indicador I3" |

En los dos casos, el informe completo (`/report`) tardó entre 1,7 y 3,3 s.

**Matices observados en el LLM:**

- **En M1, una mezcla de conceptos.** El modelo escribió "se asocian a sunburst con confianza
  media". "Media" es la confianza del vínculo; la de la asociación es 0.9.
- **En M2, la abstención parafraseada.** El modelo no copió literalmente "Sin relación
  demostrable entre los indicadores".

Ninguno de los dos afecta el resultado. La conclusión determinística va arriba en el informe,
con la frase literal, y no depende del modelo. `depurar` verifica citas, no semántica: es el
límite conocido que declaraba el plan (§2.9).

## Verificación

- `pytest`: **384 pruebas en verde**, frente a 370; las 14 nuevas son:
  - **`tests/test_informe_lote.py` (12):**
    - Contenido con relación: 7 secciones, valores como código, `metadatos` igual al GET,
      bloques del prompt y sin nombres de pulses.
    - Abstención literal.
    - Sin entidades, el LLM no se llama.
    - Si el LLM falla, el informe sale igual.
    - Se depuran las citas a `E-V99`, a `T9999` y las "evidencias" sin `E-*`.
    - El prompt queda acotado en el peor caso: 20 URL largas y 190 vínculos dan 16.000
      caracteres o menos y un aviso de recorte.
    - Los pendientes no impiden el informe.
    - 400 y 404.
    - Versiones.
    - Historial de validación con la decisión vigente en `GET /batches`.
    - Validación 404 y 422.
    - Sentencias iguales con 2 y con 20.
  - **`tests/test_e2e_scenarios.py` (+2):** los escenarios 3 y 4 como lote.
- **Mutaciones:** cada una se aplicó por separado, la suite la detectó y el archivo se
  restauró.
  - Quitar el corte de "sin entidades".
  - Poner el nombre del pulse en el prompt.
  - Quitar el tope de vínculos.
  - Escribir los valores sin código.
  - Una lectura por miembro al generar el informe.
- **Migración**, en una base desechable:
  - `upgrade head` aplica las 4 revisiones.
  - `alembic check` responde "No new upgrade operations detected".
  - `downgrade -1` deja solo `batches` y `batch_items`.
  - `upgrade head` vuelve a aplicarla.

### Criterios de aceptación

| # | Criterio | Estado |
|---|---|---|
| 1 | 201 con 7 secciones; "Sin relación demostrable entre los indicadores" literal en el escenario 3; valores como código | ✅ |
| 2 | Si ningún miembro participa, el LLM no se llama: `no_llamado` con motivo | ✅ (con el guard del conftest) |
| 3 | Si el LLM falla → 201 con "Análisis narrativo no disponible" y el motivo, sin cambios en el resto | ✅ |
| 4 | `E-V99`, `T9999` y evidencia sin `E-*` se descartan y se cuentan | ✅ |
| 5 | El prompt tiene `E-LOTE`, `E-I*` y `E-V*`, sin nombres de pulses; 16.000 caracteres o menos con 20 miembros | ✅ (en vivo: unos 7.000 con 2 o 3 miembros) |
| 6 | Dos validaciones → dos filas en orden; 404 y 422 | ✅ |
| 7 | Las mismas sentencias con 2 y con 20 al generar el informe | ✅ (con mutación) |
| 8 | Las pruebas e2e de los escenarios 3 y 4 como lote → de "Parcial" a "Cumple" | ✅ |

## Diferencias con el plan

- **Validación del informe completo, sin `vinculo` por ahora**, como estaba previsto. La
  validación por vínculo queda para la 7f opcional.
- **`descartados` incluye los ítems `eliminado`**, además de los inválidos y duplicados: para
  el informe, todos son entradas que no aportan un miembro.

## Observaciones

- **Migración en Supabase.** Se aplicó el 2026-10-10, con tu aprobación, después de probarla
  en las bases locales desechables. `alembic current` responde `f9c2e4b21c9c (head)`, y la
  inspección confirma las dos tablas y sus índices.
- **Frontend.** Lo que sigue (7d y 7e) ya tiene todo el contrato de la API:
  - `POST /batches`, `GET /batches` y `GET /batches/{id}`, este último con `correlacion`,
    `informes` y `validaciones`;
  - `POST /batches/{id}/report`, que necesita el timeout de 120 s del frontend;
  - `POST /batch-reports/{id}/validate`.
