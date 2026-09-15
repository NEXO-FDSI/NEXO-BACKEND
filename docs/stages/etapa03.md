# Etapa 3 — Ingesta de indicadores

## Contexto

Backend (FastAPI) del proyecto de enriquecimiento de inteligencia de
amenazas. Las
Etapas 1 y 2 ya están completas: existe la conexión a PostgreSQL en
Supabase gestionada por Alembic, el modelo de datos de las 8 tablas
(`app/db/models.py`), los schemas Pydantic Base/Create/Read por entidad
(`app/schemas/`), y una capa de repositorios genérica
(`app/db/repositories/`) con tests corriendo contra un Postgres local en
Docker.

Todavía no existe ningún endpoint de negocio (solo `/health`), ni el
paquete `app/ingestion/`.

## Objetivo

Exponer `POST /indicators`, que reciba un indicador (IP, dominio, hash o
URL), valide su formato según el tipo declarado, y lo persista en la
tabla `indicators` — rechazando con un error claro cualquier indicador
mal formado.

## Alcance

- Módulo `app/ingestion/` con la lógica pura de validación de formato por
  tipo (sin depender de FastAPI).
- Endpoint `POST /indicators` en `app/api/`.
- Manejo explícito del caso de `valor` duplicado (la columna ya tiene
  constraint `unique` desde la Etapa 1).
- Tests de los validadores y del endpoint.

## Fuera de alcance

- No implementar deduplicación "inteligente" (normalización de
  mayúsculas, defanging, variantes) — eso es la Etapa 4. Aquí solo se
  maneja el caso de valor idéntico ya existente (constraint unique).
- No implementar enriquecimiento, correlación con ATT&CK, ni componente
  de IA.
- No agregar `GET /indicators` ni otros endpoints — solo `POST
  /indicators`. La verificación de persistencia se hace en los tests
  consultando directamente la base de datos de test, no vía un endpoint
  de lectura.
- No modificar el esquema de las 8 tablas ni las migraciones existentes.
- No tocar el frontend.

## Reglas de validación por tipo (referencia obligatoria)

| Tipo | Regla de validación |
|---|---|
| `ip` | Debe ser una dirección IPv4 o IPv6 válida. Usar el módulo estándar `ipaddress` (`ipaddress.ip_address(valor)` dentro de un `try/except ValueError`) — sin agregar dependencias nuevas. |
| `domain` | Debe cumplir el patrón `^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$` (sin guiones al inicio/fin de cada etiqueta, con un TLD de al menos 2 letras). |
| `hash` | Debe ser una cadena hexadecimal pura de exactamente 32 (MD5), 40 (SHA-1) o 64 (SHA-256) caracteres. Regex: `^[a-fA-F0-9]{32}$`, `^[a-fA-F0-9]{40}$` o `^[a-fA-F0-9]{64}$`. |
| `url` | Debe iniciar con `http://` o `https://`, y al parsearla con `urllib.parse.urlparse` debe tener `scheme` en `{"http", "https"}` y `netloc` no vacío. |

El campo `tipo` en el request debe estar restringido a estos cuatro
valores exactos: `"ip"`, `"domain"`, `"hash"`, `"url"` (usar
`Literal["ip", "domain", "hash", "url"]` en el schema Pydantic, no un
`str` libre).

## Contrato del endpoint

`POST /indicators`

- Request body: `tipo` (uno de los 4 valores), `valor` (string), `fuente`
  (string opcional) — reutilizar/extender `IndicatorCreate` de
  `app/schemas/indicator.py`.
- **201 Created** + `IndicatorRead` si el indicador es válido y se
  persiste correctamente.
- **422 Unprocessable Entity** si `tipo` no es uno de los 4 valores
  permitidos, o si `valor` no cumple la regla de formato de su tipo. El
  detalle del error debe indicar claramente cuál fue el problema.
- **409 Conflict** si `valor` ya existe en la base de datos (constraint
  unique) — con un mensaje explícito como `"El indicador ya existe"`, no
  dejar que la `IntegrityError` de SQLAlchemy se propague como error 500.

## Tareas

1. Revisar el estado actual del repositorio: confirmar que las Etapas 1 y
   2 están aplicadas (modelos, schemas, repositorios, tests contra Docker
   funcionando) antes de escribir código nuevo.
2. Crear `app/ingestion/validators.py` con una función por tipo
   (`is_valid_ip`, `is_valid_domain`, `is_valid_hash`, `is_valid_url`) y
   una función dispatcher `validate_indicator(tipo: str, valor: str) ->
   bool` que aplique la regla correspondiente según la tabla de la
   sección anterior.
3. Actualizar `app/schemas/indicator.py`: cambiar el campo `tipo` de
   `IndicatorCreate` a `Literal["ip", "domain", "hash", "url"]`, y
   agregar un `model_validator` (Pydantic v2, `mode="after"`) que llame a
   `validate_indicator` y levante un `ValueError` con mensaje claro si el
   formato no corresponde al tipo declarado.
4. Crear `app/api/indicators.py` con un `APIRouter`, el endpoint `POST
   /indicators` usando `Depends(get_db)`, que use
   `indicator_repository.create()` (de la Etapa 2) dentro de un
   `try/except` que capture `IntegrityError` de SQLAlchemy y la traduzca
   a `HTTPException(status_code=409, detail="El indicador ya existe")`.
5. Registrar el router en `app/main.py` (`app.include_router(...)`).
6. Escribir `tests/test_ingestion_validators.py`: casos válidos e
   inválidos para cada uno de los 4 tipos (mínimo 2 casos por tipo: uno
   válido, uno inválido).
7. Escribir `tests/test_indicators_api.py`: usando `TestClient` de
   FastAPI con el `get_db` sobreescrito para apuntar al Postgres de test
   (reutilizar el fixture de `conftest.py` de la Etapa 2, extendiéndolo
   si hace falta para exponer un `TestClient`). Casos: creación exitosa
   (201, y confirmar en la base de datos de test que el registro existe),
   tipo inválido (422), formato inválido por tipo (422, uno por cada uno
   de los 4 tipos), y valor duplicado (409).

## Reglas de implementación

- La lógica de validación de formato vive en `app/ingestion/`, no
  directamente en el endpoint — el endpoint solo orquesta.
- No agregues dependencias nuevas — todo lo necesario está en la
  librería estándar de Python (`ipaddress`, `re`, `urllib.parse`) y lo ya
  instalado (Pydantic, SQLAlchemy).
- No captures excepciones genéricas (`except Exception`) — captura
  específicamente `IntegrityError` para el caso de duplicado; cualquier
  otro error de base de datos debe propagarse.
- Sigue usando el `get_db` y los repositorios de la Etapa 2 tal como
  están — no los reescribas.

## Verificación

```bash
docker compose -f docker-compose.test.yml up -d
pytest -v tests/
```

- Todos los tests (validadores + endpoint) deben pasar en verde.
- Prueba manual adicional con el servidor corriendo:
  ```bash
  uvicorn app.main:app --reload --port 8000
  curl -X POST http://localhost:8000/indicators \
    -H "Content-Type: application/json" \
    -d '{"tipo": "ip", "valor": "8.8.8.8"}'
  ```
  Debe responder `201` con el indicador creado.
- Repetir el mismo `curl` una segunda vez — debe responder `409`.
- `curl` con `{"tipo": "ip", "valor": "no-es-una-ip"}` debe responder `422`.
- El endpoint `/health` sigue respondiendo igual que antes.

## Criterios de aceptación

- `POST /indicators` valida correctamente el formato según el tipo
  declarado para los 4 tipos definidos en el alcance.
- Indicadores válidos se persisten correctamente en la tabla `indicators`.
- Formatos inválidos se rechazan con `422` y un mensaje claro.
- Valores duplicados se rechazan con `409`, sin excepciones sin manejar.
- No se implementó ninguna lógica de deduplicación "inteligente" ni
  normalización — eso queda para la Etapa 4.

## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados/modificados.
- Output completo de `pytest -v`.
- Resultado de las pruebas manuales con `curl` (los tres casos: éxito,
  duplicado, formato inválido).
- Cualquier problema encontrado y cómo se resolvió, o si quedó pendiente.

## Restricciones

- No avanzar a la Etapa 4.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar el esquema de las 8 tablas ni las migraciones existentes.
- Revisar primero el estado actual del repositorio antes de generar código.