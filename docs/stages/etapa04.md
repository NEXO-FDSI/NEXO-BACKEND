# Etapa 4 — Normalización

## Contexto

Backend (FastAPI) del proyecto de enriquecimiento de inteligencia de
amenaza. La
Etapa 3 ya está completa: existe `app/ingestion/validators.py` (validación
de formato por tipo), el endpoint `POST /indicators` en `app/api/`, y el
`model_validator` de `IndicatorCreate` en `app/schemas/indicator.py` que
llama a `validate_indicator(tipo, valor)` sobre el valor **tal como llega**
en el request — sin ninguna normalización previa.

Esto tiene un problema real: los indicadores de threat intel suelen
llegar "defanged" (ej. `hxxp://ejemplo[.]com`, para evitar clics
accidentales) o con variaciones de mayúsculas/minúsculas. Hoy esos casos
se rechazan como formato inválido, cuando en realidad son indicadores
legítimos solo ofuscados. Además, dos representaciones del mismo
indicador (`EXAMPLE.COM` vs `example.com.`) hoy se tratarían como
distintas y ambas se persistirían, violando el objetivo de no generar
duplicados lógicos.

## Objetivo

Normalizar cada indicador a una forma canónica **antes** de validar su
formato y antes de persistirlo, de modo que: (a) indicadores defanged o
con variaciones de caso se acepten correctamente, y (b) representaciones
lógicamente equivalentes del mismo indicador colapsen al mismo valor
canónico, aprovechando el constraint `unique` ya existente en `valor`
para que el 409 de la Etapa 3 actúe como deduplicación real.

## Alcance

- Módulo `app/normalization/` con la lógica pura de normalización por
  tipo (sin depender de FastAPI).
- Modificar el `model_validator` de `IndicatorCreate` para normalizar
  **antes** de validar formato.
- Tests de normalización y de deduplicación end-to-end vía el endpoint.

## Fuera de alcance

- No modificar el endpoint `POST /indicators` en sí, ni los repositorios.
- No cambiar las reglas de validación de formato de la Etapa 3 — solo
  cambia el momento en que se ejecutan (después de normalizar).
- No implementar enriquecimiento, correlación con ATT&CK, ni componente
  de IA.
- No agregar endpoints nuevos.
- No tocar el frontend.

## Reglas de normalización por tipo (referencia obligatoria)

| Tipo | Normalización aplicada, en este orden |
|---|---|
| `ip` | 1) trim. 2) refang. 3) parsear con `ipaddress.ip_address()` y usar `str(...)` como forma canónica (normaliza mayúsculas y compresión de IPv6). Si falla el parseo, devolver el resultado de los pasos 1-2 sin lanzar excepción — la validación de formato de la Etapa 3 se encargará de rechazarlo. |
| `domain` | 1) trim. 2) refang. 3) lowercase completo. 4) quitar un punto final si existe (`example.com.` → `example.com`). |
| `hash` | 1) trim. 2) lowercase completo. |
| `url` | 1) trim. 2) refang. 3) lowercase **solo** el `scheme` y el `netloc` (host) — dejar path/query/fragment sin modificar, porque pueden ser case-sensitive en el servidor destino. Usar `urllib.parse.urlsplit`/`urlunsplit`. |

**Refang** (aplica a `ip`, `domain` y `url`, no a `hash`) — reemplazar en
este orden:
```
"hxxps://" -> "https://"
"hxxp://"  -> "http://"
"[.]"      -> "."
"(.)"      -> "."
"[dot]"    -> "."
"[:]"      -> ":"
```

## Tareas

1. Revisar el estado actual del repositorio: confirmar que la Etapa 3
   está aplicada (validadores, endpoint, manejo de 409) antes de escribir
   código nuevo.
2. Crear `app/normalization/normalizer.py` con:
   - `refang(valor: str) -> str`
   - `normalize_ip(valor: str) -> str`
   - `normalize_domain(valor: str) -> str`
   - `normalize_hash(valor: str) -> str`
   - `normalize_url(valor: str) -> str`
   - `normalize_indicator(tipo: str, valor: str) -> str` (dispatcher)
   Todas siguiendo exactamente las reglas de la tabla anterior.
3. Modificar el `model_validator` (mode="after") de `IndicatorCreate` en
   `app/schemas/indicator.py` para que, en este orden:
   1. Normalice `self.valor` con `normalize_indicator(self.tipo,
      self.valor)` y reasigne el resultado a `self.valor`.
   2. Ejecute `validate_indicator(self.tipo, self.valor)` de la Etapa 3
      **sobre el valor ya normalizado**, no sobre el original.
4. No modificar `app/api/indicators.py` ni los repositorios — el valor
   persistido queda canónico automáticamente por el cambio en el schema.
5. Escribir `tests/test_normalization.py`: casos unitarios por tipo
   cubriendo refanging, mayúsculas/minúsculas, IPv6 comprimido, trailing
   dot en dominio, y al menos un caso de entrada inválida que no debe
   lanzar excepción (debe devolver el mejor esfuerzo, tolerante a
   errores).
6. Escribir/extender `tests/test_indicators_api.py` con un test de
   deduplicación end-to-end: `POST /indicators` con un indicador (ej.
   `"http://Example.COM/Path"`), luego `POST /indicators` con una
   variante lógicamente equivalente (ej. `"hxxp://EXAMPLE[.]com/Path"`) —
   la segunda petición debe responder `409`.
7. Confirmar con un test que una entrada verdaderamente inválida (ej.
   `tipo="ip"`, `valor="no-es-una-ip"`) sigue respondiendo `422`, nunca
   `500`, después de pasar por la normalización.

## Reglas de implementación

- Todas las funciones de `app/normalization/` deben ser tolerantes a
  errores: si un valor no se puede normalizar completamente, devuelven
  el mejor esfuerzo (trim + refang) sin lanzar excepción. La decisión de
  si el resultado es válido o no la toma exclusivamente la validación de
  formato de la Etapa 3, que corre después.
- El orden es siempre **normalizar → validar formato** — nunca al revés.
- No agregues dependencias nuevas (todo con librería estándar: `re` o
  reemplazos de string simples, `ipaddress`, `urllib.parse`).
- No dupliques las reglas de validación de formato de la Etapa 3 dentro
  del módulo de normalización — son responsabilidades separadas.

## Verificación

```bash
docker compose -f docker-compose.test.yml up -d
pytest -v tests/
```

- Todos los tests deben pasar en verde.
- Prueba manual con el servidor corriendo:
  ```bash
  uvicorn app.main:app --reload --port 8000

  curl -X POST http://localhost:8000/indicators \
    -H "Content-Type: application/json" \
    -d '{"tipo": "domain", "valor": "hxxp://EXAMPLE[.]COM"}'
  # (nota: para domain no debería llevar scheme; usar un valor de
  # dominio puro defanged, ej. "EXAMPLE[.]COM" -> debe responder 201
  # con valor persistido como "example.com")

  curl -X POST http://localhost:8000/indicators \
    -H "Content-Type: application/json" \
    -d '{"tipo": "domain", "valor": "example.com."}'
  # debe responder 409 (colapsó al mismo valor canónico "example.com")
  ```
- Confirmar en la base de datos de test que el valor persistido está en
  su forma canónica (minúsculas, refanged, sin trailing dot).
- `/health` sigue respondiendo igual que antes.

## Criterios de aceptación

- Indicadores defanged o con variaciones de mayúsculas se aceptan y se
  normalizan correctamente antes de persistirse.
- Representaciones lógicamente equivalentes del mismo indicador colapsan
  al mismo valor canónico y la segunda petición responde `409`.
- Ninguna entrada, válida o inválida, produce un error `500` — las
  entradas realmente mal formadas siguen respondiendo `422`.
- No se modificó el endpoint, los repositorios, ni las reglas de
  validación de formato de la Etapa 3 más allá de reordenar cuándo se
  ejecutan.

## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados/modificados.
- Output completo de `pytest -v`.
- Resultado de las pruebas manuales con `curl` (indicador normal, y el
  par equivalente que debe dar 409 en el segundo).
- Cualquier problema encontrado y cómo se resolvió, o si quedó pendiente.

## Restricciones

- No avanzar a la Etapa 5.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar el esquema de las 8 tablas ni las migraciones existentes.
- Revisar primero el estado actual del repositorio antes de generar código.