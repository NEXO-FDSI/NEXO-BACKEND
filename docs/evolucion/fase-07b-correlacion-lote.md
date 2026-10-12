# Fase 7b — Correlación entre los indicadores de un lote

Fecha: 2026-10-10. Segunda fase del plan de la Fase 7 (`fase-07-campanas-plan.md`, §2.6).

**Objetivo:** decidir con reglas fijas qué indicadores de un lote tienen una relación
demostrable, citando la evidencia de cada vínculo, y declarar la abstención cuando no la hay.
El cálculo es determinístico, al vuelo y no escribe nada.

## Qué se hizo

- **`app/correlation/lote.py`** (nuevo, lógica pura). `correlacionar_lote(items,
  investigaciones, index)` trabaja sobre los snapshots de `construir()` y devuelve:
  - `indicadores`: ref `I1…`, estado, entidad, severidad, confianza, contradicciones,
    cobertura y estado de cada fuente.
  - `vinculos`: pares con sus `senales` y su confianza.
  - `agrupaciones`, `conclusion`, `cobertura` y `cadena_ataque`.
- **`GET /batches/{id}`** agrega `correlacion`. No suma sentencias SQL: la prueba de conteo de
  la 7a (con 2 y con 20 indicadores) sigue pasando sin cambios.
- **`app/reporting/severity.py::evaluar`** reúne severidad, concordancia, contradicciones y
  confianza en una sola función. La usan `generate_report` y el lote, así que los dos nunca
  discrepan. El comportamiento de `/report` no cambió: todas sus pruebas pasan sin tocarlas.

### Reglas

| Regla | Implementación |
|---|---|
| **Elegibilidad (invariante 4)** | Participa solo un miembro correlacionado con entidad resuelta. El resto queda `sin_entidad`, `sin_correlacionar` o `sin_enriquecer` y no genera vínculos. Un benigno nunca resuelve, así que queda fuera |
| **Pulse compartido** (fuerte, OTX) | Mismo `id` de pulse en los dos, con `indicator_count ≤ MAX_INDICADORES_PULSE` (el mismo filtro de volcados de la Fase 6). Se calcula con un índice invertido, en O(total de pulses). La señal lista hasta 5 pulses con su nombre, que solo se muestra en la UI |
| **Infraestructura** (fuerte, estructura de los valores) | El host de una URL es un dominio o una IP del lote ("está alojado en"), o un dominio es subdominio de otro dominio del lote. Las IPv6 se comparan en forma canónica |
| **Misma entidad** (contextual, correlación de NEXO) | Mismo `entity_id`. El detalle cita la asociación y las fuentes de cada lado, y si el nombre es ambiguo en ATT&CK, lo dice |
| **Técnicas y tácticas** | **Nunca son señal.** `_vinculos` no las lee; solo `_cadena_ataque`, ordenada por táctica según ATT&CK 19.1 y con `varias_entidades` cuando las documentan entidades distintas |
| **Confianza del par** | `alta`: señales fuertes de 2 o más orígenes. `media`: de uno. `baja`: solo la misma entidad |
| **Agrupaciones** | Componentes conexos de los vínculos `alta` o `media`. Su confianza es la del vínculo más débil, y `tecnicas_comunes` es la intersección de las técnicas de sus miembros |
| **Conclusión** | `relacion_demostrable` o `sin_relacion_demostrable`. En el segundo caso, el texto empieza con "Sin relación demostrable entre los indicadores." y explica por qué. Si varios miembros comparten la entidad, se agrega "…lo que no prueba que pertenezcan a la misma campaña" |
| **Cobertura** | Por fuente, qué miembros verificó y cuáles no se pudieron verificar (`FALLIDOS`, que no significa "sin evidencia"). Es `parcial` si queda algo sin verificar o pendiente |

## Resultados

### Datos congelados (pytest)

**Escenario 4** (`2c4a…102e` + `ervsystem.com`):

- `V1 = I1–I2` con dos señales: 4 pulses enfocados compartidos y la misma entidad, sunburst.
- Confianza **media**, agrupación `A1 = {I1, I2}` y 36 técnicas comunes.
- Conclusión: "Relación demostrable entre I1 y I2 (A1, confianza media). Comparten la
  entidad atribuida sunburst, lo que no prueba que pertenezcan a la misma campaña."

**Escenario 3** (lazarus group, remcos, dridex):

- **0 vínculos.** Las tres entidades comparten entre 5 y 20 técnicas por par, y ninguna de esas
  técnicas genera un vínculo (invariante 3).
- Cobertura conjunta de 15 tácticas en orden ATT&CK, con el solapamiento marcado.
- Conclusión: "Sin relación demostrable entre los indicadores. Ningún par comparte un pulse
  enfocado de OTX ni infraestructura."

### En vivo

Se corrió con OTX, ThreatFox y VirusTotal reales, contra una base local desechable (no
Supabase), con los casos M1 y M2 del plan:

| Caso | Resultado |
|---|---|
| M1 (escenario 4) | Igual que con los datos congelados: 4 pulses enfocados compartidos, `A1` de confianza media y 36 técnicas comunes. VirusTotal confirma sunburst en I1 (`popular_threat_name`), y la cobertura es completa con las tres fuentes |
| M2 (escenario 3) | 0 vínculos, aunque 28 de 116 técnicas están documentadas para varias entidades. VirusTotal agotó su cupo en el tercer indicador, por lo que la cobertura queda **parcial**, con VirusTotal sin verificar en I3 |

Tiempos medidos en M1: `/enrich` tardó 3–8 s, por la red de las tres fuentes, y `/correlate`
25–53 ms en el Postgres local.

## Verificación

- `pytest`: **370 pruebas en verde**, frente a 355; las 15 nuevas están en
  `tests/test_correlacion_lote.py`:
  - **Tres por la API con los datos congelados:** los escenarios 4 y 3, y un lote mixto con
    un participante, un benigno, uno sin `/correlate`, uno solo registrado y un descarte,
    donde cada uno queda con su estado y nada de eso genera vínculos.
  - **Doce sintéticas sobre la función pura**, una por regla:
    - solo misma entidad → confianza baja y sin agrupación;
    - pulse más infraestructura → alta;
    - infraestructura sola (subdominio, URL con IP y puerto, IPv6) → media;
    - dos URL en el mismo host → se agrupan solo a través del dominio;
    - técnicas compartidas → no son señal;
    - frontera de volcados (1.000 cuenta, 1.001 no);
    - la agrupación vale lo que su vínculo más débil;
    - un nombre ambiguo se declara;
    - con menos de dos participantes no hay relaciones que evaluar.
- **Mutaciones:** cada una se aplicó al módulo por separado y la suite la detectó. Después se
  restauró el archivo.
  - Contar las técnicas compartidas como señal (invariante 3).
  - Que la misma entidad suba la confianza.
  - Quitar el filtro de volcados.
  - Dejar participar a los indicadores sin entidad (invariante 4).

### Criterios de aceptación

| # | Criterio | Estado |
|---|---|---|
| 1 | Escenario 4: `V1` con pulse compartido (4) y misma entidad; confianza media; `A1`; relación demostrable; 36 técnicas comunes | ✅ (congelado y en vivo) |
| 2 | Escenario 3: 0 vínculos; el texto empieza con "Sin relación demostrable entre los indicadores"; 5 tácticas o más | ✅ (15 tácticas) |
| 3 | Mutaciones sintéticas: solo entidad → baja; pulse e infraestructura → alta; técnicas compartidas sin vínculo y con `varias_entidades`; volcado de 1.001 no cuenta | ✅ |
| 4 | Benignos, sin correlacionar y sin enriquecer fuera de los vínculos, cada uno con su estado en `cobertura` | ✅ |
| 5 | Las pruebas de `/report` pasan sin tocarlas | ✅ |
| 6 | El conteo de sentencias de `GET /batches/{id}` es igual con 2 y con 20 | ✅ |

## Diferencias con el plan

- **`evaluar` quedó en `severity.py`, no en `reporting/service.py`.** `severity.py` es puro;
  así el módulo del lote no importa el servicio del informe ni el del LLM.
- **Dos URL en el mismo host no se vinculan solas.** El plan las vinculaba, pero el host
  puede ser una plataforma compartida, como docs.google.com, y eso uniría indicadores sin
  relación. Se agrupan a través del dominio cuando el analista lo incluye en el lote. Es más
  conservador y queda probado.
- **`tecnicas_comunes` es la lista de IDs**, no un conteo: el informe de la 7c la necesita.

## Observaciones para las siguientes fases

- **Estado de VirusTotal tras agotar el cupo.** Si VirusTotal se quedó sin cupo durante
  `/enrich`, el GET muestra su estado como `no_disponible` ("sin respuesta registrada"), no
  como `limite_cuota`: el motivo no se persiste, porque un fallo no se cachea. La cobertura lo
  cuenta bien (sin verificar). La UI de la 7d debe decir "sin verificar", no "límite de
  cuota".
- **Severidad con VirusTotal.** En vivo, la severidad de los dos indicadores de M1 subió a
  "crítica" por VirusTotal. En los tests, donde solo OTX está configurada, es "alta". Es
  esperado.

## Siguiente

7c: informe conjunto (Markdown y metadatos con esta `correlacion` congelada), análisis del LLM
con los bloques `E-LOTE`, `E-I#` y `E-V#`, y validación con historial. Trae la segunda
migración (`batch_reports`, `batch_validation`).
