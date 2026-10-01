# Fase 2 — Fuentes de enriquecimiento: OTX + ThreatFox + VirusTotal

Fecha: 2026-09-30.

## Diseño

- **Contrato `Proveedor`** (`typing.Protocol`, igual que el `VectorStore` existente):
  `nombre`, `etiqueta`, `tipos`, `configurado`, `soporta(tipo, valor)`,
  `consultar(tipo, valor) -> dict` (crudo) y `resumir(crudo, tipo, valor) -> dict`
  (normalizado). **Agregar una fuente = un archivo en `app/enrichment/providers/` + una
  línea en `PROVEEDORES`.**
- **Resumen normalizado**, idéntico para toda fuente: `tiene_evidencia`, `veredicto`
  (`malicioso | sospechoso | sin_evidencia | benigno_conocido`), `familias`, `etiquetas`,
  `detecciones`, `confianza`, `primera_vez`, `ultima_vez`, `referencia_url`. Todo texto de
  terceros pasa por `limpiar()`: recorte a 64 caracteres y *charset* `[\w .:/@-]`. Es
  input no confiable que terminará en la UI y en el prompt del LLM.
- **Estado por fuente:** `con_evidencia`, `sin_evidencia`, `error`, `limite_cuota`,
  `no_soportado`, `no_configurado`, `omitido`. Un fallo **nunca** se convierte en
  "sin evidencia".
- **Orquestación** (`get_or_fetch_enrichment`): la caché por fuente se lee primero; lo
  pendiente se consulta en paralelo con `ThreadPoolExecutor`. Solo el HTTP va a hilos:
  la `Session` no es *thread-safe*, así que la caché se escribe en el hilo del request.
- **OTX sigue siendo obligatoria** (la correlación se construye sobre sus pulses): si
  falla → 502 como siempre. Las demás fuentes que respondieron **se guardan igual**, así
  "Reintentar" solo vuelve a consultar OTX y no gasta otra vez cuota de VirusTotal.
- **HTTP resiliente:** un reintento ante fallo de red o 5xx (0,5 s de espera). 429 →
  `limite_cuota`, sin reintento; 4xx, sin reintento. Aplicado también al cliente OTX.
- **OPSEC:** una IP no pública (`not ip.is_global`: privadas, loopback, link-local,
  reservadas, ULA IPv6…) no se envía a ninguna fuente. `/enrich` → 200 con estado
  `omitido`, y `/correlate` da "sin asociación" en vez de un 400.
- **Contrato aditivo:** `/enrich` conserva `fuente`, `tiene_evidencia` y `detalle` (OTX) y
  agrega `fuentes[]`. El frontend actual sigue funcionando sin cambios. Nuevo
  `GET /status`: fuentes configuradas y proveedor de IA, sin secretos y sin llamar a
  terceros. `/health` no cambia (hay dos tests que lo fijan como contrato).

| Fuente | Consulta | Particularidades verificadas contra la API real |
|---|---|---|
| OTX | `GET /indicators/{sección}/{valor}/general` (cliente existente) | `validation` con `whitelist`/`false_positive` y 0 pulses → `benigno_conocido` |
| ThreatFox | `POST search_hash` (MD5/SHA-256) o `search_ioc` | `no_result` = sin evidencia; 403 con clave inválida; una IP sin puerto encuentra sus entradas `ip:puerto`; SHA-1 → `no_soportado`; solo guarda IoCs recientes |
| VirusTotal | `GET /api/v3/{files,ip_addresses,domains,urls}/{id}` | 404 = sin registros (no es error); id de URL = base64url sin relleno; nunca `POST /urls` (escanearía y publicaría la URL) |

## Prueba real (APIs en vivo, Postgres de tests con rollback)

| Indicador | OTX | ThreatFox | VirusTotal |
|---|---|---|---|
| WannaCry SHA-256 | caída 2× → **502** (20,7 s) | cacheada igual | cacheada igual |
| `ervsystem.com` | caída 2× → **502** | cacheada igual | cacheada igual |
| `8.8.8.8` | `benigno_conocido` (se recuperó en el reintento, 11 s) | sin evidencia (0,6 s) | 0/91 (0,5 s) |
| `140.233.190.114` (C2 activo) | 16 pulses | **Aisuru**, confianza 100 | **7/91** maliciosos |
| `10.0.0.5` | omitido | omitido | omitido (0 ms, nada sale a la red) |
| WannaCry SHA-1 | *Cobalt Strike* (50 pulses) | `no_soportado` | **wannacry, 65/70** |

**Hallazgo operativo:** el 2026-09-30 OTX estuvo degradado. Con `curl` directo, 5 de 6
consultas quedaron colgadas 40 s y la otra respondió en 0,5 s. ThreatFox y VirusTotal
respondieron siempre en < 0,6 s. Consecuencias para la demo: (1) el reintento de OTX es
necesario y ya rescató dos consultas; (2) **precargar la caché** de los indicadores de la
demo es imprescindible, no opcional.

**Hallazgo analítico:** para el SHA-1 de WannaCry, OTX sugiere *Cobalt Strike* (el patrón
de volcados agregados documentado en la Etapa 9) y VirusTotal lo contradice. La
concordancia entre fuentes (F4) debe hacer visible este tipo de desacuerdo.

## Verificación

- `pytest`: **242 passed**.
- Garantía estructural nueva en `conftest.py`: `sin_fuentes_reales` (autouse). Sin ella,
  los tests existentes salían a VirusTotal real en cuanto el `.env` tuvo la clave; se
  detectó en esta fase.
- 33 tests nuevos (`tests/test_providers.py` + 2 de reintento OTX en `test_enrichment.py`):
  saneamiento, reintentos, 429, formas reales de las tres fuentes, estados del
  orquestador, caché por fuente, persistencia parcial ante 502 de OTX, IPs no públicas
  (5 variantes, IPv6 incluida), paralelismo y `/status` sin secretos.
- Mutaciones verificadas: sin la omisión de IPs no públicas fallan 5 tests; con
  `max_workers=1` (en serie) falla el de paralelismo.
- Se corrigió un error propio durante la fase: parchear `time.sleep` para acelerar los
  reintentos anulaba el test de paralelismo (`time.sleep` es global). Ahora se anula una
  constante por módulo (`ESPERA_REINTENTO`).
- Dos tests existentes se adaptaron: comparaban respuestas completas y ahora la segunda
  trae `desde_cache: true`. Comparan los datos, no los metadatos de caché.

## Pendiente (fuera del corte de demo)

- Usar las familias de ThreatFox y VirusTotal como candidatos de la etapa (a) de la
  correlación (fase 2 post-demo: exige escenarios congelados nuevos).
- TTL de caché y restricción única `(indicator_id, fuente_api)`.
- El frontend aún no muestra `fuentes[]`: se hace en la F5 (`types.ts`, `fixtures.ts`,
  pestaña Inteligencia).
