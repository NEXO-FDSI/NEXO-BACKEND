# Etapa 5 — Enriquecimiento

## Contexto

Backend (FastAPI) del proyecto de enriquecimiento de inteligencia de
amenazas (Seminario de Seguridad de la Información, Grupo 2). Las
Etapas 1-4 ya están completas: `POST /indicators` normaliza (Etapa 4) y
valida formato (Etapa 3) antes de persistir en la tabla `indicators`
(PostgreSQL/Supabase, gestionado por Alembic desde la Etapa 1), con
repositorios genéricos (Etapa 2).

Todavía no existe el paquete `app/enrichment/`, y la tabla
`enrichment_cache` (definida desde la Etapa 1) no se usa todavía.

## Objetivo

Consultar la reputación de un indicador contra **AlienVault OTX**,
cachear la respuesta en `enrichment_cache` para no repetir llamadas, y
distinguir explícitamente entre **"tiene evidencia"** y **"sin
evidencia"** — sin confundir nunca un fallo de la API externa con
ausencia de evidencia (son cosas distintas y esa distinción es central
al diseño del proyecto).

## Alcance

- Cliente HTTP hacia la API de AlienVault OTX (`app/enrichment/client.py`).
- Servicio de enriquecimiento con caché (`app/enrichment/service.py`).
- Extensión del repositorio de `enrichment_cache` con una búsqueda por
  `indicator_id` + `fuente_api`.
- Endpoint `POST /indicators/{indicator_id}/enrich`.
- Tests que mockean la llamada externa (nunca pegan a la API real de OTX).

## Fuera de alcance

- No modificar el endpoint `POST /indicators` de las Etapas 3/4 — el
  enriquecimiento se dispara aparte, con su propio endpoint.
- No implementar reintentos ni backoff — un único intento por llamada,
  con timeout de 10 segundos.
- No implementar correlación con MITRE ATT&CK ni componente de IA.
- No integrar otras fuentes de reputación (ThreatFox, VirusTotal,
  AbuseIPDB) — solo OTX en esta etapa.
- No tocar el frontend.

## Mapeo de tipo de indicador a sección de la API de OTX

La API de OTX expone `GET
https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general`
con header `X-OTX-API-KEY`. El `{section}` depende del tipo:

| `tipo` interno | Cómo determinar `section` |
|---|---|
| `ip` | `"IPv4"` si `ipaddress.ip_address(valor).version == 4`, `"IPv6"` si es `6`. |
| `domain` | Siempre `"domain"`. |
| `hash` | Según la longitud del valor normalizado: 32 → `"FileHash-MD5"`, 40 → `"FileHash-SHA1"`, 64 → `"FileHash-SHA256"`. |
| `url` | Siempre `"url"`. El valor debe ir URL-encoded en el path de la petición. |

**Determinación de evidencia**: la respuesta de OTX incluye
`pulse_info.count`. Si `pulse_info.count > 0` → **tiene evidencia**
(el indicador aparece en al menos un pulse/reporte). Si
`pulse_info.count == 0` → **sin evidencia**.

## Tareas

1. Revisar el estado actual del repositorio: confirmar que las
   Etapas 1-4 están aplicadas antes de escribir código nuevo. Confirmar
   que `REPUTATION_API_KEY` ya existe en `Settings`
   (`app/core/config.py`, desde la Etapa 1) — no crear una variable
   nueva.
2. Crear `app/enrichment/client.py`:
   - Función `resolve_otx_section(tipo: str, valor: str) -> str` que
     implemente la tabla de mapeo anterior.
   - Excepción `ReputationAPIError(Exception)`.
   - Función `fetch_reputation(tipo: str, valor: str, api_key: str) ->
     dict` que arme la URL, haga el `GET` con `httpx` (timeout de 10s) y
     el header `X-OTX-API-KEY`, y levante `ReputationAPIError` en caso de
     timeout, error de red, o `status_code != 200`. Si es 200, devuelve
     el JSON parseado.
3. Extender el repositorio de `enrichment_cache`
   (`app/db/repositories/enrichment_cache.py`) con
   `get_by_indicator_and_source(db: Session, indicator_id: int,
   fuente_api: str) -> EnrichmentCache | None`.
4. Crear `app/enrichment/service.py` con
   `get_or_fetch_enrichment(db: Session, indicator: Indicator) -> dict`:
   1. Busca en caché con `get_by_indicator_and_source(db,
      indicator.id, "alienvault_otx")`.
   2. Si existe, parsea `respuesta_json` (JSON string) y lo devuelve —
      **no** llama a la API externa.
   3. Si no existe, llama a `fetch_reputation(...)`, guarda el resultado
      crudo en `enrichment_cache` (vía el repositorio, serializando la
      respuesta a JSON string en `respuesta_json`, con `fuente_api =
      "alienvault_otx"`), y lo devuelve.
   4. Calcula `tiene_evidencia` a partir de `pulse_info.count` (ver
      sección anterior) y lo incluye en el resultado devuelto junto con
      el detalle crudo.
   - Si `fetch_reputation` levanta `ReputationAPIError`, el servicio debe
     dejarla propagar — **nunca** capturarla y devolver "sin evidencia"
     en su lugar.
5. Crear el endpoint `POST /indicators/{indicator_id}/enrich`:
   - Busca el indicador con el repositorio de `indicators` (404 si no
     existe).
   - Llama a `get_or_fetch_enrichment`.
   - **200** con `{"indicator_id": ..., "fuente": "alienvault_otx",
     "tiene_evidencia": bool, "detalle": {...}}`.
   - **502 Bad Gateway** si se captura `ReputationAPIError`, con detail
     explicando que el servicio de reputación no respondió — nunca
     devolver 200 con "sin evidencia" en este caso.
6. Escribir `tests/test_enrichment.py`:
   - Test de `resolve_otx_section` para los 4 tipos (incluyendo IPv4 e
     IPv6 por separado, y los 3 tamaños de hash).
   - Tests de `get_or_fetch_enrichment` **mockeando**
     `app.enrichment.client.fetch_reputation` (con `monkeypatch` o
     `unittest.mock.patch`): un caso con `pulse_info.count > 0` (hit), un
     caso con `pulse_info.count == 0` (miss), y un caso donde se llama
     dos veces para el mismo indicador y se confirma que el mock de
     `fetch_reputation` **solo se invocó una vez** (la segunda vino de
     caché).
   - Test del endpoint con el mock aplicado, cubriendo 200 (hit), 200
     (miss), 404 (indicador inexistente) y 502 (mock que lanza
     `ReputationAPIError`).

## Reglas de implementación

- Los tests automatizados **nunca** deben llamar a la API real de OTX —
  siempre mockear `fetch_reputation`. Esto es no negociable: correr la
  suite de tests no debe depender de red ni de una API key real.
- Un fallo de la API externa se propaga como error explícito (502) — no
  se interpreta jamás como "sin evidencia". Confundir "no pude verificar"
  con "verifiqué y no hay nada" es exactamente el tipo de error que el
  proyecto busca evitar.
- La búsqueda en caché debe evitar la llamada HTTP por completo cuando ya
  existe una entrada — no llamar "por si acaso".
- No agregues reintentos ni backoff en esta etapa.
- No modifiques el endpoint `POST /indicators` ni los repositorios de
  etapas anteriores, salvo la extensión puntual del repositorio de
  `enrichment_cache` descrita en la tarea 3.

## Verificación

```bash
docker compose -f docker-compose.test.yml up -d
pytest -v tests/
```

- Todos los tests deben pasar en verde, sin ninguna llamada de red real.
- Prueba manual con `REPUTATION_API_KEY` real de OTX en `.env` y el
  servidor corriendo:
  ```bash
  uvicorn app.main:app --reload --port 8000

  # crear un indicador conocido, ej. un hash público documentado
  curl -X POST http://localhost:8000/indicators \
    -H "Content-Type: application/json" \
    -d '{"tipo": "hash", "valor": "<hash real de prueba>"}'

  # enriquecerlo (primera vez: pega a la API real de OTX)
  curl -X POST http://localhost:8000/indicators/<id>/enrich

  # enriquecerlo de nuevo (segunda vez: debe venir de caché)
  curl -X POST http://localhost:8000/indicators/<id>/enrich
  ```
- Confirmar en la base de datos que `enrichment_cache` tiene **una sola
  fila** para ese indicador después de las dos llamadas (no dos).
- `/health` y `POST /indicators` (Etapas 3-4) siguen funcionando igual.

## Criterios de aceptación

- El endpoint distingue explícitamente "tiene evidencia" de "sin
  evidencia" según `pulse_info.count`.
- La caché evita una segunda llamada HTTP para el mismo indicador —
  verificado tanto en tests (mock llamado una vez) como manualmente
  (una sola fila en `enrichment_cache`).
- Un fallo de la API externa nunca se traduce en "sin evidencia" — se
  reporta como 502 explícito.
- Ningún test automatizado depende de red ni de una API key real.

## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados/modificados.
- Output completo de `pytest -v`.
- Resultado de la prueba manual con OTX real (confirmando que la segunda
  llamada usó caché).
- Cualquier problema encontrado (ej. límite de rate de OTX, formato de
  respuesta distinto al esperado) y cómo se resolvió, o si quedó
  pendiente.

## Restricciones

- No avanzar a la Etapa 6.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar el esquema de las 8 tablas ni las migraciones existentes.
- Revisar primero el estado actual del repositorio antes de generar código.