# Etapa 7 — Reporting y validación humana

## Contexto

Backend (FastAPI) del proyecto de enriquecimiento de inteligencia de
amenazas. Las
Etapas 1-6 ya están completas: `POST /indicators` (ingesta + normalización
+ validación), `POST /indicators/{id}/enrich` (AlienVault OTX + caché),
`POST /indicators/{id}/correlate` (resolución de entidad + recuperación
de técnicas ATT&CK, con `correlate_indicator()` en
`app/correlation/service.py`, idempotente).

Las tablas `reports` y `human_validation` (definidas desde la Etapa 1)
todavía no se usan. No existe el paquete `app/reporting/`.

## Objetivo

Generar un informe estructurado (Markdown) a partir del indicador, su
enriquecimiento y su correlación, persistirlo en `reports`, y exponer un
endpoint para que un analista lo acepte o rechace, persistiendo esa
decisión en `human_validation`.

**Todavía sin componente de IA** — el informe se genera con una plantilla
fija en Python, no con un LLM (eso es la Etapa 8, que va a reemplazar o
enriquecer esta redacción, no la estructura de datos).

## Alcance

- Módulo `app/reporting/` con la plantilla de informe y el servicio de
  generación.
- Endpoint `POST /indicators/{indicator_id}/report`.
- Endpoint `POST /reports/{report_id}/validate`.
- Schema de request dedicado para la validación (no reutilizar
  `HumanValidationCreate` tal cual, porque `report_id` debe venir de la
  URL, no del body).
- Test de integración del flujo completo indicador → informe →
  validación.

## Fuera de alcance

- No integrar ningún LLM ni generación por IA — la Etapa 8 se encarga de
  eso, reutilizando esta estructura.
- No modificar `POST /indicators`, `/enrich` ni `/correlate` de etapas
  anteriores.
- No agregar `GET /reports/{id}` — la verificación se hace consultando la
  base de datos de test directamente, igual que en etapas anteriores.
- No implementar un límite de "una sola validación por informe" — cada
  llamada a `/validate` crea una fila nueva en `human_validation`
  (permite que un informe se revise más de una vez y quede el historial
  completo; es consistente con el enfoque auditable del proyecto).
- No tocar el frontend.

## Plantilla del informe (referencia obligatoria)

`app/reporting/template.py` debe generar exactamente esta estructura
Markdown (con los valores reales interpolados):

```markdown
# Informe de indicador: {valor}

**Tipo:** {tipo}
**Fecha de generación:** {timestamp ISO 8601}
**Nivel de confianza:** {nivel_confianza}

## Enriquecimiento

- Fuente: AlienVault OTX
- Evidencia encontrada: {"Sí" | "No"}
- Reportes (pulses) que mencionan este indicador: {pulse_info.count, o 0 si no está presente}

## Resolución de entidad y técnicas ATT&CK

```

Si `correlation_result["resuelto"]` es `True`, continuar con:

```markdown
- **Entidad asociada:** {nombre} ({tipo})
- **Evidencia de asociación:** {evidencia}
- **Confianza de la asociación:** {confianza}

### Técnicas documentadas

| ID | Técnica | Táctica |
|---|---|---|
| {id} | {nombre} | {tactica} |
(una fila por cada técnica en correlation_result["tecnicas"])

**Fuente de las técnicas:** MITRE ATT&CK STIX dataset — relationship "uses"
```

Si `correlation_result["resuelto"]` es `False`, en su lugar:

```markdown
> **Sin evidencia suficiente para asociar este indicador a una entidad
> conocida.** No se atribuye ninguna técnica ATT&CK — la ausencia de
> asociación es un resultado válido, no un error del sistema.
```

Y siempre cerrar con:

```markdown
## Estado de validación

Pendiente de revisión humana.
```

## Cálculo de `nivel_confianza`

- Si `correlation_result["resuelto"]` es `True`: usar
  `correlation_result["confianza"]` (0.9 o 0.6, según la Etapa 6).
- Si es `False`: `0.0`.

## Tareas

1. Revisar el estado actual del repositorio: confirmar que las
   Etapas 1-6 están aplicadas (en particular, que
   `app/correlation/service.py` expone `correlate_indicator` y que existe
   la dependencia `get_attck_index`) antes de escribir código nuevo.
2. Crear `app/reporting/template.py` con
   `build_report_content(indicator: Indicator, enrichment_detalle: dict,
   correlation_result: dict) -> str`, implementando exactamente la
   plantilla de la sección anterior.
3. Crear `app/reporting/service.py` con `generate_report(db: Session,
   indicator: Indicator, enrichment_detalle: dict, index: AttckIndex) ->
   Report`:
   1. Llama a `correlate_indicator(db, indicator, enrichment_detalle,
      index)` (de la Etapa 6 — es idempotente, seguro llamarla de nuevo
      aunque ya se haya correlacionado antes).
   2. Construye el contenido con `build_report_content`.
   3. Calcula `nivel_confianza` según la regla de la sección anterior.
   4. Persiste con `report_repository.create()` (`indicator_id`,
      `contenido`, `nivel_confianza`).
   5. Devuelve el `Report` creado.
4. Crear `app/schemas/human_validation_request.py` (o agregar al archivo
   existente de schemas de `human_validation`) con
   `HumanValidationRequest`: `decision: Literal["aceptado",
   "rechazado"]`, `analista: str | None = None` — **sin** `report_id`
   (viene de la URL).
5. Agregar a `app/api/indicators.py` el endpoint `POST
   /indicators/{indicator_id}/report`:
   - Busca el indicador (404 si no existe).
   - Busca la entrada de `enrichment_cache` (fuente `"alienvault_otx"`).
     Si no existe → **400** con detail `"Debes ejecutar /enrich para
     este indicador antes de generar el informe"`.
   - Llama a `generate_report(db, indicator, detalle, index)` (inyectando
     `index` vía `Depends(get_attck_index)`, igual que en `/correlate`).
   - **201** con `ReportRead`.
6. Crear `app/api/reports.py` con el endpoint `POST
   /reports/{report_id}/validate`:
   - Busca el informe con `report_repository.get()` (404 si no existe).
   - Valida el body contra `HumanValidationRequest`.
   - Persiste con `human_validation_repository.create()` (`report_id`
     desde la URL, `decision`, `analista`).
   - **201** con `HumanValidationRead`.
   Registrar este router en `app/main.py`.
7. Escribir `tests/test_reporting.py`:
   - Test unitario de `build_report_content` con un
     `correlation_result` de `resuelto=True` (entidad y técnicas de
     prueba) — assert de que el Markdown contiene el nombre de la
     entidad y los IDs de las técnicas.
   - Test unitario de `build_report_content` con `resuelto=False` —
     assert de que contiene la frase "Sin evidencia suficiente".
   - Test de integración del **flujo completo**: crear un indicador vía
     `POST /indicators`, simular su enriquecimiento insertando
     directamente una fila en `enrichment_cache` (o llamando `/enrich`
     con `fetch_reputation` mockeado, igual que en la Etapa 5), llamar
     `POST /indicators/{id}/report` (201), extraer el `id` del informe,
     llamar `POST /reports/{id}/validate` con `decision="aceptado"`
     (201), y verificar directamente en la base de datos de test que
     existe la fila correspondiente en `reports` y en
     `human_validation`.
   - Test de `POST /indicators/{id}/report` sin enriquecimiento previo →
     **400**.
   - Test de `POST /reports/{id}/validate` sobre un `report_id`
     inexistente → **404**.
   - Test de `POST /reports/{id}/validate` con `decision` inválida (algo
     distinto de `"aceptado"`/`"rechazado"`) → **422**.

## Reglas de implementación

- La generación del informe reutiliza `correlate_indicator` de la
  Etapa 6 tal cual — no reimplementes esa lógica aquí.
- El contenido del informe sigue la plantilla exacta de este documento —
  no improvises el formato.
- No agregues dependencias nuevas — todo con f-strings o construcción de
  string estándar de Python.
- `POST /reports/{id}/validate` no debe impedir múltiples validaciones
  sobre el mismo informe — cada una es una fila nueva.

## Verificación

```bash
docker compose -f docker-compose.test.yml up -d
pytest -v tests/
```

- Todos los tests deben pasar, incluyendo el test de integración del
  flujo completo.
- Prueba manual con el servidor corriendo, sobre un indicador ya
  enriquecido de una etapa anterior:
  ```bash
  curl -X POST http://localhost:8000/indicators/<id>/report
  # 201, revisar que el campo "contenido" tenga el Markdown esperado

  curl -X POST http://localhost:8000/reports/<report_id>/validate \
    -H "Content-Type: application/json" \
    -d '{"decision": "aceptado", "analista": "tu nombre"}'
  # 201
  ```
- Confirmar en Supabase (o en la base de test) que ambas tablas tienen
  las filas correspondientes.
- `/health`, `/indicators`, `/enrich` y `/correlate` de etapas anteriores
  siguen funcionando igual.

## Criterios de aceptación

- El informe se genera con la estructura exacta de la plantilla, para
  los casos "resuelto" y "sin evidencia".
- `nivel_confianza` refleja correctamente la confianza de la
  correlación, o `0.0` cuando no hubo resolución.
- `POST /reports/{id}/validate` persiste correctamente la decisión del
  analista en `human_validation`.
- El flujo completo indicador → informe → validación funciona de punta a
  punta, verificado por el test de integración.
- Generar un informe sin haber enriquecido antes el indicador falla con
  `400`, no con un error no manejado.

## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados/modificados.
- Output completo de `pytest -v`.
- Resultado de las pruebas manuales con `curl` (informe generado +
  validación).
- Cualquier problema encontrado y cómo se resolvió, o si quedó
  pendiente.

## Restricciones

- No avanzar a la Etapa 8.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar el esquema de las 8 tablas ni las migraciones existentes.
- Revisar primero el estado actual del repositorio antes de generar código.