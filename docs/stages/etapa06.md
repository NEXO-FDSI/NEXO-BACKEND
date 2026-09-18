# Etapa 6 — Integración MITRE ATT&CK y correlación

## Contexto

Backend (FastAPI) del proyecto de enriquecimiento de inteligencia de
amenazas. Las
Etapas 1-5 ya están completas: `POST /indicators` normaliza y valida
(Etapas 3-4), `POST /indicators/{id}/enrich` consulta AlienVault OTX y
cachea el resultado en `enrichment_cache` (Etapa 5). El modelo de datos
incluye `entities`, `indicator_entity_link`, `techniques` y
`entity_technique_link` desde la Etapa 1, pero ninguna de esas tablas se
usa todavía.

**Esta es la etapa central del proyecto.** El documento de la propuesta
establece que un indicador no posee técnicas ATT&CK de forma intrínseca
— la relación existe únicamente de forma transitiva, mediada por una
entidad de nivel superior (malware, grupo, herramienta o campaña), en dos
tareas encadenadas y de naturaleza distinta:

1. **Resolución de entidad** — determinar si el indicador puede
   vincularse, con evidencia trazable, a una entidad conocida. El modo de
   fallo característico es la **atribución incorrecta**.
2. **Recuperación y justificación de técnicas** — una vez identificada la
   entidad, recuperar de la base de conocimiento de MITRE ATT&CK las
   técnicas documentadas para ella. El modo de fallo característico es la
   **fabricación** (proponer técnicas sin sustento).

Si la etapa (1) no alcanza evidencia suficiente, la etapa (2) **no debe
ejecutarse** — el sistema declara explícitamente la ausencia de
asociación en vez de forzarla.

## Objetivo

Cargar el dataset oficial de MITRE ATT&CK (Enterprise, STIX), construir
un índice de técnicas y de relaciones entidad→técnica, y usar ese índice
para implementar las dos etapas de correlación sobre lo que devolvió el
enriquecimiento de la Etapa 5 — persistiendo los resultados en
`entities`, `indicator_entity_link`, `techniques` y
`entity_technique_link`.

## Alcance

- Cargador del dataset STIX de MITRE ATT&CK (`app/correlation/`).
- Script de siembra (seed) que puebla la tabla `techniques` con el
  catálogo completo.
- Índice en memoria de relaciones entidad→técnica, construido una sola
  vez por proceso (no en cada request).
- Lógica de resolución de entidad (etapa a) a partir del campo `detalle`
  que ya guarda `enrichment_cache` (de la Etapa 5).
- Lógica de recuperación de técnicas (etapa b), que solo se ejecuta si
  (a) tuvo éxito.
- Endpoint `POST /indicators/{indicator_id}/correlate`.
- Extensiones puntuales a los repositorios de `entities`,
  `indicator_entity_link` y `entity_technique_link` para soportar
  get-or-create idempotente.

## Fuera de alcance

- No implementar el componente de IA / LLM ni RAG (eso es la Etapa 8) —
  aquí la resolución de entidad es determinística, basada en
  coincidencia de nombre/alias contra el catálogo de MITRE, no generada
  por un modelo de lenguaje.
- No implementar generación de informes ni validación humana (Etapa 7).
- No modificar `POST /indicators` ni `POST /indicators/{id}/enrich` de
  etapas anteriores.
- No implementar matching difuso/fuzzy ni scoring de confianza más allá
  de los dos niveles fijos definidos en este documento — es una decisión
  deliberada para no sobreingeniería en un prototipo académico.
- No tocar el frontend.

## Descarga del dataset

Si `data/attck/enterprise-attack-19.1.json` no existe todavía en el
repositorio, descárgalo antes de empezar:

```bash
mkdir -p data/attck
curl -o data/attck/enterprise-attack-19.1.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json
```

Agrega `ATTCK_STIX_PATH` a `Settings` (`app/core/config.py`) con default
`"data/attck/enterprise-attack-19.1.json"`.

## Cómo extraer el índice del STIX (referencia obligatoria)

El bundle STIX es una lista de objetos en `objects`. Filtrar siempre los
objetos con `revoked: true` o `x_mitre_deprecated: true` — no deben
formar parte del índice.

**Técnicas**: objetos con `type == "attack-pattern"`.
- `id` del catálogo ATT&CK (ej. `"T1566"` o `"T1566.001"` para
  sub-técnicas): tomar el primer elemento de `external_references` donde
  `source_name == "mitre-attack"`, campo `external_id`.
- `nombre`: campo `name` del objeto.
- `tactica`: tomar el primer elemento de `kill_chain_phases`, campo
  `phase_name`, convertir guiones a espacios y capitalizar (ej.
  `"initial-access"` → `"Initial Access"`). Si un objeto tiene varias
  fases, usar solo la primera — nuestra tabla `techniques` solo admite
  una `tactica` por técnica, es una simplificación deliberada.

**Entidades**: objetos con `type` en `{"malware", "intrusion-set",
"tool", "campaign"}`.

| STIX `type` | `tipo` interno |
|---|---|
| `malware` | `malware` |
| `intrusion-set` | `grupo` |
| `tool` | `herramienta` |
| `campaign` | `campaña` |

Para cada uno, el nombre canónico es el campo `name`; los alias
adicionales están en `aliases` o `x_mitre_aliases` si existen (algunos
tipos no los tienen — está bien que la lista quede vacía).

**Relación entidad→técnica**: objetos con `type == "relationship"`,
`relationship_type == "uses"`, donde `source_ref` apunta a uno de los
tipos de entidad de la tabla anterior y `target_ref` apunta a un
`attack-pattern`. Resolver ambos extremos por su `id` STIX interno
(distinto del `external_id` de ATT&CK) usando un diccionario `id ->
objeto` construido primero con todos los objetos del bundle.

## Estructura del índice en memoria

Crear `app/correlation/attck_loader.py` con una dataclass:

```python
@dataclass
class AttckIndex:
    techniques: dict[str, dict]       # technique_id -> {"nombre": str, "tactica": str}
    entity_type: dict[str, str]       # nombre canónico (lowercase) -> tipo
    entity_aliases: dict[str, str]    # alias (lowercase) -> nombre canónico (lowercase)
    entity_techniques: dict[str, list[str]]  # nombre canónico (lowercase) -> [technique_id, ...]
```

Y una función `load_attck_index(path: str) -> AttckIndex` que parsea el
bundle una sola vez y construye estas cuatro estructuras. Y
`find_entity(index: AttckIndex, candidate: str) -> str | None`: dado un
nombre candidato, lo busca case-insensitive primero en `entity_type`
(nombre canónico), luego en `entity_aliases`; si coincide con un alias,
devuelve el nombre canónico al que apunta. Si no hay coincidencia,
devuelve `None`.

## Resolución de entidad a partir del enriquecimiento (etapa a)

Fuente de candidatos, **en este orden de prioridad**, a partir del
`detalle` (respuesta cruda de OTX) guardado en `enrichment_cache`:

1. `pulse_info.pulses[].malware_families[].display_name` — señal
   estructurada, confianza **0.9** si hace match.
2. `pulse_info.pulses[].tags` — señal más ruidosa, confianza **0.6** si
   hace match (y no hubo match ya en el punto 1).

**No usar** el campo `pulse_info.pulses[].name` (título libre del pulse)
como candidato — es texto libre y es exactamente el tipo de fuente que
puede llevar a atribución incorrecta.

Si ningún candidato de ninguna de las dos fuentes hace match contra el
índice → la etapa (a) **falla explícitamente**: no se crea ninguna fila
en `entities` ni en `indicator_entity_link`, y la etapa (b) no se llama
en absoluto.

## Tareas

1. Revisar el estado actual del repositorio: confirmar que las
   Etapas 1-5 están aplicadas antes de escribir código nuevo.
2. Descargar el dataset STIX si no existe (ver sección anterior) y
   agregar `ATTCK_STIX_PATH` a `Settings`.
3. Crear `app/correlation/attck_loader.py` con `AttckIndex`,
   `load_attck_index()` y `find_entity()`, siguiendo exactamente las
   reglas de extracción de esta guía.
4. Cargar el índice **una sola vez por proceso** al iniciar la
   aplicación: usar el `lifespan` de FastAPI (o evento `startup`) para
   construir `AttckIndex` y guardarlo en `app.state.attck_index`. Crear
   una dependencia `get_attck_index(request: Request) -> AttckIndex` que
   lo exponga a los endpoints.
5. Crear `scripts/seed_techniques.py`: script standalone (ejecutable con
   `python -m scripts.seed_techniques`) que llama a
   `load_attck_index()` y, por cada técnica del índice, hace
   get-or-create en la tabla `techniques` vía el repositorio (buscar
   por `id` con `technique_repository.get()`; si no existe, crear). Debe
   ser idempotente — correrlo dos veces no debe fallar ni duplicar.
6. Extender los repositorios:
   - `entity_repository`: agregar `get_by_nombre(db, nombre: str) ->
     Entity | None`.
   - `indicator_entity_link_repository`: agregar
     `get_by_indicator_and_entity(db, indicator_id: int, entity_id: int)
     -> IndicatorEntityLink | None`.
   - `entity_technique_link_repository`: agregar
     `get_by_entity_and_technique(db, entity_id: int, technique_id: str)
     -> EntityTechniqueLink | None`.
7. Crear `app/correlation/service.py`:
   - `resolve_entity_from_enrichment(detalle: dict, index: AttckIndex) ->
     dict | None` — implementa la lógica de la sección "Resolución de
     entidad" y devuelve `{"nombre_canonico": str, "tipo": str,
     "confianza": float, "evidencia": str}` o `None`.
   - `retrieve_techniques_for_entity(nombre_canonico: str, index:
     AttckIndex) -> list[str]` — devuelve la lista de `technique_id`
     desde `index.entity_techniques`. Función pura, sin acceso a base de
     datos.
   - `correlate_indicator(db: Session, indicator: Indicator, detalle:
     dict, index: AttckIndex) -> dict`:
     1. Llama a `resolve_entity_from_enrichment`. Si devuelve `None`,
        retorna inmediatamente `{"resuelto": False, "entity": None,
        "confianza": None, "evidencia": None, "tecnicas": []}` — **sin
        llamar a `retrieve_techniques_for_entity` ni tocar la base de
        datos**.
     2. Si resolvió: get-or-create `Entity` (nombre, tipo).
        Get-or-create `IndicatorEntityLink` (indicator_id, entity_id,
        evidencia, confianza) — si ya existe un link para ese
        indicador+entidad, no dupliques.
     3. Llama a `retrieve_techniques_for_entity`. Para cada
        `technique_id`: get-or-create `EntityTechniqueLink` (entity_id,
        technique_id, `fuente_attck="MITRE ATT&CK STIX dataset —
        relationship 'uses'"`).
     4. Retorna `{"resuelto": True, "entity": {...}, "confianza": float,
        "evidencia": str, "tecnicas": [{"id", "nombre", "tactica"}, ...]}`.
8. Crear el endpoint `POST /indicators/{indicator_id}/correlate`:
   - Busca el indicador (404 si no existe).
   - Busca la entrada de `enrichment_cache` para ese indicador (fuente
     `"alienvault_otx"`). Si no existe → **400 Bad Request** con detail
     `"Debes ejecutar /enrich para este indicador antes de
     correlacionar"`.
   - Llama a `correlate_indicator` con el `detalle` parseado de la
     caché.
   - **200** con el resultado.
9. Escribir `tests/test_correlation.py`:
   - Test del **caso crítico**: mockear/parchar
     `retrieve_techniques_for_entity` y llamar a `correlate_indicator`
     con un `detalle` sin ningún candidato que haga match (ej.
     `pulse_info.count == 0` o `pulses` vacío) — verificar que el
     resultado es `resuelto: False`, y **assert explícito de que
     `retrieve_techniques_for_entity` nunca fue llamado**. Verificar
     también que no se creó ninguna fila nueva en `entities` ni en
     `indicator_entity_link`.
   - Test del caso positivo: usando un `AttckIndex` de prueba construido
     a mano (no el archivo STIX real — ver regla de implementación
     siguiente), con una entidad falsa y un par de técnicas falsas, y un
     `detalle` cuyo `malware_families` hace match con esa entidad —
     verificar `resuelto: True`, confianza `0.9`, y que las técnicas
     devueltas coinciden con las del índice de prueba.
   - Test de confianza `0.6` cuando el match viene solo de `tags`.
   - Test de idempotencia: llamar `correlate_indicator` dos veces con el
     mismo indicador y mismo `detalle` — confirmar que no se duplican
     filas en `indicator_entity_link` ni en `entity_technique_link`.
   - Test separado para `attck_loader.py`, usando un bundle STIX
     sintético pequeño (2-3 objetos: un `attack-pattern`, un `malware`,
     una `relationship` "uses" entre ellos) como fixture — **no** el
     archivo real de 19.1 completo — que confirme que `load_attck_index`
     construye correctamente las cuatro estructuras del `AttckIndex`.

## Reglas de implementación

- **La regla más importante de esta etapa**: si la resolución de entidad
  no encuentra match, la recuperación de técnicas nunca se invoca. Esto
  debe ser verificable por inspección del código (la llamada a
  `retrieve_techniques_for_entity` debe estar estrictamente dentro del
  bloque condicional de éxito) y por el test que lo assert explícitamente.
- Los tests de `service.py` usan un `AttckIndex` construido a mano en el
  test, no el archivo STIX real completo — mantiene los tests rápidos y
  no dependientes de un archivo de ~30-50 MB.
- El índice STIX se carga **una sola vez por proceso**, nunca en cada
  request — si detectas que se está reparseando el archivo en cada
  llamada al endpoint, es un error de esta etapa.
- Todas las operaciones de creación (`Entity`, `IndicatorEntityLink`,
  `EntityTechniqueLink`) deben ser get-or-create idempotentes — correlate
  puede llamarse más de una vez para el mismo indicador sin generar
  duplicados.
- No agregues dependencias nuevas — todo con la librería estándar
  (`json`, `dataclasses`) y lo ya instalado.
- No modifiques el esquema de las 8 tablas ni las migraciones existentes.

## Verificación

```bash
python -m scripts.seed_techniques
# debe reportar cuántas técnicas insertó (esperar varios cientos)

docker compose -f docker-compose.test.yml up -d
pytest -v tests/
```

- Todos los tests deben pasar, incluyendo el assert explícito de que
  `retrieve_techniques_for_entity` no se llama cuando (a) falla.
- Confirmar en Supabase que la tabla `techniques` tiene varios cientos de
  filas después de correr el seed.
- Prueba manual con el servidor corriendo: tomar un indicador ya
  enriquecido (de la Etapa 5) cuya respuesta de OTX tenga
  `malware_families`, y llamar `POST
  /indicators/{id}/correlate` — confirmar que la respuesta trae
  `resuelto: true` y una lista de técnicas no vacía. Repetir con un
  indicador cuyo enriquecimiento no tuvo evidencia (`pulse_info.count ==
  0`) y confirmar `resuelto: false`, `tecnicas: []`.
- Llamar `/correlate` sobre un indicador que nunca pasó por `/enrich` —
  debe responder `400`, no fallar con un error no manejado.

## Criterios de aceptación

- La cadena de dos etapas está implementada tal como la describe el
  documento del proyecto: la etapa (b) nunca se ejecuta si la etapa (a)
  no resolvió una entidad.
- El catálogo completo de técnicas ATT&CK Enterprise está sembrado en la
  tabla `techniques`.
- Un indicador con evidencia suficiente resuelve a una entidad y recupera
  técnicas reales del dataset oficial, con `fuente_attck` trazable.
- Un indicador sin evidencia suficiente declara explícitamente
  `resuelto: false`, sin fabricar ninguna técnica.
- Las operaciones son idempotentes — correlacionar el mismo indicador dos
  veces no duplica filas.

## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados/modificados.
- Output del script de siembra (cuántas técnicas se insertaron).
- Output completo de `pytest -v`.
- Resultado de las pruebas manuales (caso resuelto, caso sin evidencia,
  caso sin enriquecimiento previo).
- Cualquier problema encontrado (ej. discrepancias en el formato del
  STIX, campos ausentes en algunos objetos) y cómo se resolvió, o si
  quedó pendiente.

## Restricciones

- No avanzar a la Etapa 7.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar el esquema de las 8 tablas ni las migraciones existentes.
- Revisar primero el estado actual del repositorio antes de generar código.