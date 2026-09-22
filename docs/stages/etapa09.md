# Etapa 9 — Testing end-to-end, documentación y hardening

## Contexto

Backend (FastAPI) del proyecto de enriquecimiento de inteligencia de
amenazas. Las
Etapas 1-8 ya están completas: ingesta + normalización + validación
(`POST /indicators`), enriquecimiento vía OTX con caché (`/enrich`),
correlación determinística de dos etapas contra MITRE ATT&CK
(`/correlate`), generación de informe con análisis grounded por LLM+RAG
(`POST /indicators/{id}/report`), y validación humana
(`POST /reports/{id}/validate`).

Cada etapa anterior se probó de forma aislada (tests unitarios y de
integración por módulo, contra Postgres local en Docker, con mocks para
servicios externos). Lo que falta es: (1) demostrar que el pipeline
completo cumple los seis escenarios de prueba que describe el
documento de la propuesta del proyecto, de forma reproducible; (2) dejar
la documentación de la API (OpenAPI/Swagger) presentable; y (3) un pase
de hardening básico apropiado para un prototipo académico — no
seguridad de nivel empresarial, pero sí lo mínimo no negociable.

**Esta es la última etapa del plan de 9 antes de iniciar la integración
con el frontend.**

## Objetivo

Dejar el backend con: (1) una suite de tests end-to-end que ejecuta los
6 escenarios oficiales del proyecto de forma reproducible y sin
depender de red; (2) documentación OpenAPI clara y organizada por
tags; (3) manejo de errores consistente que no filtra detalles internos;
y (4) un checklist de seguridad básica verificado.

## Alcance

- Dataset de prueba curado y congelado para los 6 escenarios (respuestas
  de enriquecimiento fijadas como fixtures, no llamadas en vivo a OTX).
- Suite de tests end-to-end (`tests/test_e2e_scenarios.py`) que ejercita
  el pipeline completo (ingesta → enrich → correlate → report) para
  cada uno de los 6 escenarios.
- Tags, summaries y descriptions en todos los endpoints existentes, para
  una documentación OpenAPI legible en `/docs`.
- Un exception handler global que traduzca cualquier error no manejado
  a una respuesta 500 genérica, sin exponer tracebacks ni detalles de
  SQLAlchemy al cliente.
- Checklist de seguridad básica verificado (CORS, `.env` fuera de git,
  sin secretos en logs).
- Verificación de que el stack completo (no solo el de test) levanta
  correctamente con `docker compose`.
- Actualización final del `README.md` del backend reflejando el estado
  real del proyecto terminado.

## Fuera de alcance

- No implementar autenticación ni autorización multiusuario — el
  documento del proyecto define explícitamente que el prototipo no
  incluye eso (ver sección de alcance del documento: "sin autenticación
  multiusuario ni funciones de administración").
- No implementar rate limiting, WAF, ni infraestructura de seguridad de
  nivel productivo — está fuera del alcance de un prototipo académico.
- No modificar la lógica de negocio de ninguna etapa anterior (Etapas
  1-8) — esta etapa consolida y verifica, no reimplementa.
- No iniciar ningún trabajo del frontend.
- No implementar CI/CD (pipeline de GitHub Actions, etc.) salvo que se
  pida explícitamente — no estaba en el alcance original del proyecto.

## Los 6 escenarios oficiales (referencia obligatoria)

Tal como los define el documento de la propuesta, sección 5.1:

| # | Escenario | Entrada | Resultado esperado |
|---|---|---|---|
| 1 | Amenaza conocida | Hash de malware documentado públicamente | Informe identifica la familia de malware y al menos una técnica ATT&CK. `resuelto: true`, confianza alta. |
| 2 | Información incompleta | IP sin reputación ni reportes previos | Confianza baja, no se atribuyen técnicas sin sustento. `resuelto: false`. |
| 3 | Múltiples técnicas | Conjunto heterogéneo de indicadores (dominio de phishing, hash de payload, IP de C2) | Cada indicador correlaciona con técnicas distintas; en conjunto cubren varias fases de la cadena de ataque. |
| 4 | Misma campaña | Indicadores de un mismo reporte/campaña documentada | Los indicadores resuelven a la misma entidad o a entidades relacionadas, con técnicas comunes. |
| 5 | Indicador benigno | IP o dominio de infraestructura legítima reconocida | `resuelto: false` o confianza muy baja — no se fuerza ninguna técnica. |
| 6 | Asociación incorrecta | Indicador ambiguo con similitud superficial a un patrón conocido, sin relación real | El sistema puede proponer una hipótesis de baja confianza; el mecanismo de validación humana permite **rechazarla** (`POST /reports/{id}/validate` con `decision="rechazado"`), y esa corrección queda registrada. |

## Tareas

### 1. Dataset de prueba congelado

Crear `data/test_dataset/scenarios.json` con un objeto por escenario:

```json
{
  "scenario_1_amenaza_conocida": {
    "indicator": {"tipo": "hash", "valor": "<hash real de prueba>"},
    "enrichment_response": { /* respuesta de OTX capturada y congelada */ },
    "expected": {"resuelto": true, "min_confianza": 0.6}
  },
  "scenario_2_informacion_incompleta": { ... },
  "scenario_3_multiples_tecnicas": {
    "indicators": [ /* 2-3 indicadores heterogéneos */ ],
    ...
  },
  "scenario_4_misma_campana": { ... },
  "scenario_5_indicador_benigno": {
    "indicator": {"tipo": "ip", "valor": "8.8.8.8"},
    "enrichment_response": { /* respuesta real u honesta simulando bajo pulse_info.count */ },
    "expected": {"resuelto": false}
  },
  "scenario_6_asociacion_incorrecta": {
    "indicator": { ... },
    "enrichment_response": { ... },
    "expected": {"resuelto": true, "validation_decision": "rechazado"}
  }
}
```

Las respuestas de `enrichment_response` deben ser JSON reales
previamente obtenidos de OTX (o, si no hay uno disponible para algún
caso, construidos a mano de forma realista siguiendo la estructura de
`pulse_info` que ya conoce el proyecto desde la Etapa 5) — nunca
llamadas en vivo dentro de un test. Esto es lo que garantiza la
reproducibilidad que promete el documento de la propuesta.

### 2. Tests end-to-end

Crear `tests/test_e2e_scenarios.py`. Para cada uno de los 6 escenarios:

1. Cargar el fixture correspondiente de `scenarios.json`.
2. `POST /indicators` para crear el/los indicador(es).
3. Mockear `fetch_reputation` (Etapa 5) para que devuelva el
   `enrichment_response` congelado, y llamar `/enrich`.
4. Llamar `/correlate` y comparar el resultado contra `expected`.
5. Llamar `/report` — mockeando `generate_analysis` del componente de
   IA (Etapa 8) para no depender de Ollama en la suite automatizada —
   y verificar que el informe se generó con el contenido esperado
   (sección de técnicas presente o ausencia de asociación, según el
   caso).
6. Para el escenario 6 específicamente: además de lo anterior, llamar
   `POST /reports/{id}/validate` con `decision="rechazado"` y verificar
   que la fila se persiste correctamente en `human_validation`.

### 3. Documentación OpenAPI

- Agregar `tags=["Indicators"]`, `tags=["Enrichment"]`,
  `tags=["Correlation"]`, `tags=["Reports"]` (o la agrupación que
  corresponda a los routers ya existentes) a cada `APIRouter` o a cada
  endpoint.
- Agregar `summary` y `description` cortos a cada endpoint existente
  (`POST /indicators`, `/enrich`, `/correlate`, `/report`,
  `POST /reports/{id}/validate`) explicando en una frase qué hace y qué
  precondición requiere (ej. "Requiere haber ejecutado /enrich
  previamente").
- Configurar `title`, `description` y `version` en el constructor de
  `FastAPI()` en `app/main.py`, con una descripción breve del proyecto.

### 4. Manejo de errores consistente

- Agregar un exception handler global en `app/main.py` con
  `@app.exception_handler(Exception)` que capture cualquier excepción
  no manejada explícitamente por los endpoints, loguee el detalle
  completo del lado del servidor (no al cliente), y devuelva
  `{"detail": "Error interno del servidor"}` con status 500 — sin
  traceback, sin mensaje de SQLAlchemy, sin ninguna información interna
  en la respuesta HTTP.
- Revisar que los `HTTPException` ya lanzados en etapas anteriores
  (404, 400, 409, 502, 422) sigan propagándose normalmente — el handler
  global solo debe capturar lo verdaderamente no manejado.

### 5. Checklist de seguridad básica

Verificar (y corregir si hace falta) cada uno de estos puntos:

- `CORS_ORIGINS` en `Settings` nunca incluye `"*"` — solo el origen
  real del frontend (`http://localhost:5173` en desarrollo).
- `.env` está en `.gitignore` en ambos repos y **nunca** fue commiteado
  (`git log --all --full-history -- .env` no debe mostrar nada).
- Ninguna API key (`LLM_API_KEY`, `REPUTATION_API_KEY`, credenciales de
  Supabase) aparece hardcodeada en el código fuente ni en los tests.
- Los logs de la aplicación no imprimen el contenido de `Settings` ni
  las variables de entorno completas.
- `data/attck/*.json` y `data/chroma/` siguen excluidos de git (ya
  definido desde la Etapa 1, confirmar que se mantuvo).

### 6. Verificación del stack completo con Docker

- Confirmar que existe un `docker-compose.yml` (distinto del
  `docker-compose.test.yml` de tests) que levanta el backend apuntando
  a las variables de `.env` reales. Si no existe todavía, crearlo:
  un servicio `backend` construido desde el `Dockerfile` ya existente,
  exponiendo el puerto 8000, con `env_file: .env`.
- Levantar con `docker compose up --build` y confirmar que `/health`
  responde correctamente desde el contenedor.

### 7. Actualización del README

Actualizar `README.md` del backend, dejarlo completo y bien documentado, agregar tags, arquitectura, diagramas etc.., documentar todos los endpoints disponibles con
un ejemplo de uso por endpoint, y las instrucciones finales de arranque
(local con Ollama + Docker, y con `docker compose`).

## Reglas de implementación

- Los tests end-to-end de esta etapa **no deben depender de red** —
  nada de llamadas reales a OTX, Ollama, ni a la instancia de Supabase
  de producción. Todo mockeado o corriendo contra el Postgres local de
  Docker, igual que en etapas anteriores.
- No modifiques la lógica de `correlate_indicator`, `generate_report`,
  ni ningún servicio de negocio de las Etapas 1-8 — si un test end-to-end
  falla, el problema se diagnostica y se reporta, no se "arregla"
  cambiando silenciosamente el comportamiento de una etapa anterior sin
  decírmelo explícitamente.
- El exception handler global no debe interceptar ni ocultar los
  `HTTPException` ya lanzados intencionalmente — solo errores no
  manejados.
- No agregues dependencias nuevas salvo que sean estrictamente
  necesarias para los tests (no debería hacer falta ninguna).

## Verificación

```bash
docker compose -f docker-compose.test.yml up -d
pytest -v tests/
# todos los tests existentes (Etapas 1-8) + los 6 escenarios nuevos
# deben pasar en verde

docker compose up --build -d
curl http://localhost:8000/health
docker compose down
```

- Abrir `http://localhost:8000/docs` manualmente y confirmar que los
  endpoints están agrupados por tags, cada uno con summary/description
  legible — revisión visual, repórtala en el resultado.
- Confirmar el checklist de seguridad de la tarea 5, uno por uno, y
  reportar el resultado de cada verificación.
- Provocar deliberadamente un error no manejado (ej. apagar la conexión
  a la base de datos y hacer una petición) y confirmar que la respuesta
  es un 500 genérico sin traceback ni detalles internos — luego
  restaurar la conexión.

## Criterios de aceptación

- Los 6 escenarios oficiales del documento del proyecto pasan como
  tests automatizados, reproducibles, sin depender de red.
- La documentación en `/docs` está organizada por tags, con
  summary/description en cada endpoint.
- Ningún error no manejado expone detalles internos al cliente.
- El checklist de seguridad básica está verificado y documentado.
- El stack completo levanta correctamente con `docker compose up`.
- El `README.md` refleja el estado final real del backend.

## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados/modificados.
- Output completo de `pytest -v` (incluyendo los 6 escenarios nuevos).
- Resultado del checklist de seguridad, punto por punto.
- Confirmación de que `docker compose up --build` levanta el stack
  completo y `/health` responde.
- Capturas o descripción de cómo quedó `/docs` organizado.
- Cualquier problema encontrado (ej. algún escenario que no pasó con
  los datos disponibles) y cómo se resolvió, o si quedó pendiente y por
  qué.

## Restricciones

- No iniciar trabajo del frontend.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar la lógica de negocio de las Etapas 1-8 sin reportarlo
  explícitamente como hallazgo antes de tocarla.
- Revisar primero el estado actual del repositorio antes de generar código.
- Esta es la última etapa del plan — al terminar, reporta que el backend
  queda listo para iniciar la integración con el frontend.