# Fase 1 — Fundamentos del backend

Fecha: 2026-09-30. Alcance: robustez y rendimiento sin cambiar el comportamiento
observable del pipeline ni el contrato de la API.

## Cambios

| Hallazgo | Cambio | Archivos |
|---|---|---|
| D4/D5 · correlación N+1 | Técnicas y links se crean con 2 SELECT en lote (`id IN (...)`) + `add_all` + 1 `flush`. Se elimina `get_by_entity_and_technique` (quedó sin uso) | `app/correlation/service.py`, `app/db/repositories/technique.py`, `app/db/repositories/entity_technique_link.py` |
| D2 · fallo del LLM silencioso | `LLMServiceError` se sigue absorbiendo (el informe sale igual) pero se registra con `WARNING` y el motivo | `app/ai_component/service.py` |
| D13 · claves en texto plano | `REPUTATION_API_KEY` y `LLM_API_KEY` son `SecretStr`; se leen con `.get_secret_value()` solo en el punto de uso | `app/core/config.py`, `app/enrichment/service.py`, `app/ai_component/llm_client.py` |
| D12 · entradas sin tope | `valor` ≤ 2048, `fuente` ≤ 200, `analista` ≤ 100 → 422 | `app/schemas/indicator.py`, `app/schemas/human_validation.py` |
| D14 · credenciales CORS | `allow_credentials=False` (la API no usa cookies). Se mantiene el rechazo de `*` | `app/main.py`, `app/core/config.py` |
| D15 · sin logging | `logging.basicConfig` con `LOG_LEVEL` (nuevo, por defecto `INFO`); `httpx` nunca por debajo de `INFO` (en DEBUG imprime cabeceras con API keys); middleware que registra método, ruta, estado y duración de cada request | `app/main.py`, `app/core/config.py`, `.env.example` |

## Resultado medido

Mismo procedimiento que la Fase 0 (Postgres de tests, bundle real 19.1, rollback).

| Escenario | Técnicas | Queries 1.ª antes → después | Repetida antes → después |
|---|---:|---:|---:|
| 1 WannaCry | 16 | 102 → **10** | 34 → **4** |
| 3 Lazarus Group | 93 | 552 → **10** | 188 → **4** |
| 3 Remcos | 38 | 192 → **10** | 78 → **4** |
| 3 Dridex | 15 | 74 → **10** | 32 → **4** |
| 4 SUNBURST (hash) | 36 | 172 → **10** | 74 → **4** |
| 4 SUNBURST (dominio, entidad ya creada) | 36 | 76 → **6** | 74 → **4** |
| 6 BlackCat | 21 | 100 → **10** | 44 → **4** |

Con el RTT medido a Supabase (~75–79 ms), el costo de BD de un "Análisis completo"
(correlate + re-correlación en `/report`) pasa de ~55 s a ~1 s para Lazarus Group y de
~10 s a ~1 s para WannaCry. El número de queries ya no depende del número de técnicas.

## Verificación

- `pytest`: **199 passed** (193 previos sin modificar su expectativa + 6 nuevos).
- Tests nuevos:
  - `test_queries_constantes_sin_importar_el_numero_de_tecnicas`: 100 técnicas no pueden
    costar más de 2 queries extra que 3. Mutación verificada: con el código anterior falla
    con *592 queries para 100 técnicas vs 24 para 3*.
  - `test_fallo_del_llm_devuelve_none_sin_propagar`: ahora también exige el motivo en el log.
  - `test_campos_demasiado_largos_son_422` (×2) y `test_validate_422_analista_demasiado_largo`.
  - `test_claves_no_aparecen_al_imprimir_settings`.
  - `test_cors_no_habilita_credenciales`. Mutación verificada: falla con `allow_credentials=True`.
- `pytest -v tests/test_e2e_scenarios.py`: los 6 escenarios oficiales siguen en verde.
- Arranque real con `uvicorn`: `/health` → 200; log `INFO app.http: GET /health -> 200 en 3 ms`;
  `fuente` de 250 caracteres → 422 `string_too_long`.

## Notas

- `BaseRepository.create` sigue haciendo `refresh` tras cada inserción; ya no está en el
  camino caliente de la correlación, así que no se tocó.
- El `/report` sigue re-correlacionando (idempotente). Con 4 queries ya no justifica
  cambiar el flujo antes de la demo.
- `README.md` tenía un cambio local previo del usuario; no se modificó en esta fase.
