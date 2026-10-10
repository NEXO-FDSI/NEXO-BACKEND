# Fase 6 — Las tres fuentes habilitan todo el pipeline

Fecha: 2026-10-01.

## Problema

Hasta la Fase 5, ThreatFox y VirusTotal se consultaban y resumían, pero OTX era la única
puerta: si OTX fallaba había 502 aunque las otras tuvieran evidencia, `/correlate` y
`/report` exigían la caché de OTX (`detalle_otx`) y la etapa (a) solo leía sus pulses. Un
indicador presente solo en ThreatFox o VirusTotal terminaba como "sin evidencia".

## Diseño

- **Evidencia normalizada (`SourceEvidence`)**: es la entrada que ya devolvía `/enrich` en
  `fuentes[]` (`fuente`, `estado`, `error`, `resumen`), sin renombrar nada. El resumen suma
  `tecnicas_attck` (IDs que la fuente cita: OTX `attack_ids`) y `referencias` (solo
  http/https, máx. 5). VirusTotal no aporta técnicas: `/behaviour_mitre_trees` gastaría
  una segunda consulta de la cuota.
- **Ninguna fuente es obligatoria.** Una fuente que falla queda `error`/`limite_cuota` y
  las demás siguen. **502 solo si fallan todas las consultadas.** `tiene_evidencia` es
  combinado y `cobertura` (`completa | parcial`) dice si un "sin evidencia" es completo.
- **Cupo de VirusTotal**: ventana deslizante en memoria, 4 consultas/60 s. Sin cupo no se
  llama: la fuente queda `limite_cuota` y "Reintentar" la vuelve a intentar. No se espera,
  porque bloquearía `/enrich` más allá de los 30 s del frontend. Es por proceso.
- **Puerta de `/correlate` y `/report`**: `crudos_enriquecidos` = cualquier fila de caché
  (o IP no pública). Antes: solo la de OTX.
- **Etapa (a) combinada** (`resolve_entity_from_enrichment`): familias (0.9) de OTX
  (`malware_families`), ThreatFox (`malware_printable`) y VirusTotal
  (`popular_threat_name`); luego etiquetas (0.6). OTX vota una vez por pulse no masivo;
  ThreatFox y VirusTotal, una vez cada una. **Gana la entidad respaldada por más fuentes
  distintas**, desempate por votos y luego orden de aparición. Con solo OTX el resultado es
  idéntico al de la Etapa 9 (los escenarios e2e no cambiaron).
- **Procedencia**: la correlación devuelve `fuentes` (las que sustentan la entidad) y cada
  técnica `fuentes` + `reportada_por` (las que citan ese ID). Un ID citado por una fuente
  **nunca agrega** una técnica: solo corrobora una de la cadena entidad → técnicas. Se
  recalcula desde la caché en los GET: **sin migración**.
- **Contradicciones** (`detectar_contradicciones`), nunca resueltas en silencio:
  `entidad_distinta` (las familias de una fuente apuntan a otra entidad ATT&CK),
  `vt_limpio` (VirusTotal analizó el indicador y 0 motores lo detectan, pero otra fuente lo
  reporta), `lista_blanca` (OTX lo tiene en lista blanca y otra fuente lo reporta). Que
  ThreatFox no lo tenga no es contradicción: solo cubre IoCs recientes.

### Regla de confianza (`calcular_confianza`)

Primera regla que aplica:

| Nivel | Regla |
|---|---|
| `sin_evidencia` | Ninguna fuente que respondió lo encontró (el motivo dice cuáles respondieron y cuáles no se pudieron verificar) |
| `baja` | Hay alguna contradicción; o evidencia débil: sin entidad y una sola fuente, o entidad inferida solo de etiquetas |
| `alta` | Entidad respaldada por 2 o más fuentes, sin contradicciones |
| `media` | El resto: una fuente con familia de malware, o varias fuentes sin entidad común |

Si alguna fuente falló, se agrega el motivo "no se pudo verificar en …: no significa sin
evidencia". `reports.nivel_confianza` (Float) sigue siendo la confianza de la asociación
(0.9 / 0.6 / 0.0) para no romper la API.

### Severidad: confianza mínima de ThreatFox

Antes, cualquier registro de ThreatFox subía la severidad al menos a "alta" (y a "crítica"
con una entidad fuerte), sin importar su `confidence_level`. Ahora solo cuenta como señal
fuerte con confianza ≥ `CONFIANZA_MINIMA` (50/100, `providers/threatfox.py`, el mismo umbral
que separa "malicioso" de "sospechoso" en el adaptador). Por debajo, o sin confianza
informada, es señal débil ("media") y el motivo lo dice: "ThreatFox lo registra (Aisuru)
con confianza 25/100, por debajo del mínimo de 50". El resto de reglas de severidad no
cambia, y la correlación (etapa a) sigue usando ThreatFox sin este filtro.

### Los volcados agregados no son evidencia

Un pulse de OTX con más de 1.000 indicadores (`MAX_INDICADORES_PULSE`) ya se ignoraba en
la correlación y en el resumen; ahora tampoco cuenta como evidencia. OTX tiene evidencia
solo si quedan pulses enfocados (`count` menos los volcados listados), y la severidad
cuenta solo esos. Un indicador que solo figura en volcados queda `sin_evidencia` (o
`benigno_conocido` si además está en lista blanca, el caso de 8.8.8.8). Si OTX lista menos
pulses que `count`, los no listados siguen contando: no se puede saber si son volcados. La
UI lo explica en la pestaña de OTX en vez de decir "no tiene registros".

## IA e informe

- `E-COR` lleva la procedencia y las contradicciones como hechos calculados por NEXO.
  Las reglas del prompt exigen citar `E-OTX`/`E-TF`/`E-VT` de donde sale cada dato y
  recuerdan que una fuente caída no es "sin evidencia". El grounding no cambia.
- El Markdown pasa de "Enriquecimiento (OTX)" a **Evidencia por fuente** (tabla, fuentes
  que respondieron, **fuentes no disponibles**), sección **Contradicciones**, cabecera con
  **Nivel de confianza + motivos** y columna **Procedencia** en las técnicas.
- `metadatos` suma `confianza`, `contradicciones` y `cobertura` (JSON, sin migración).

### Selección semántica de técnicas para la IA

Hasta aquí el "RAG" recuperaba el texto de ATT&CK por ID (`get_by_ids`) y elegía las
técnicas del contexto repartiéndolas por táctica: los embeddings sembrados en Chroma no se
consultaban. Ahora, al generar el informe, se calcula el embedding de una consulta que
describe la evidencia del indicador (tipo, entidad, familias y etiquetas de las fuentes con
evidencia) y se ordenan las técnicas **de la entidad** por similitud coseno con los
embeddings sembrados. Las `MAX_TECNICAS` más afines van al contexto. La similitud solo
ordena: nunca agrega una técnica que la etapa (b) no haya recuperado.

Si el endpoint de embeddings (Ollama local) falla o tarda más de 10 s, se vuelve al reparto
por táctica y el informe se genera igual. `metadatos.ia.seleccion` guarda método, consulta,
motivo y puntajes; la UI lo muestra en "Contexto enviado al modelo".

Medido con datos reales (IP de C2 de AsyncRAT, 20 técnicas): la selección semántica prioriza
Multi-hop Proxy, Dynamic Resolution, DGA e Ingress Tool Transfer (Command and Control); el
reparto por táctica incluía Video Capture y Debugger Evasion.

## API

Sin endpoints nuevos: la evidencia normalizada ya viaja en `fuentes[]` de `/enrich`,
`GET /indicators/{id}` y `GET /investigations`. Un endpoint por fuente obligaría a tres
requests más por caso y duplicaría la construcción en lote. Ninguna respuesta cruda sale.

## Verificación

- `tests/test_multifuente.py` (13 tests): solo ThreatFox, solo VirusTotal, las tres
  coincidentes (confianza alta, procedencia múltiple), contradicciones `vt_limpio`,
  `entidad_distinta` y `lista_blanca`, fuente caída con otra con evidencia, todas sin
  evidencia, las tres caídas (502), etapa (b) sin ejecutar si (a) falla, procedencia en
  `GET`, adaptadores (técnicas, referencias seguras) y cupo de VirusTotal.
- Tests existentes actualizados por el cambio de supuesto: `test_providers.py` (OTX caída
  ya no es 502 si otra fuente responde), `test_reporting.py` y `test_ai_component.py`
  (plantilla sin `detalle` de OTX; contexto con contradicciones en vez de concordancia),
  `test_severity.py` (OTX también se contrasta), `test_correlation.py` y
  `test_consultas.py` (campo `fuentes` nuevo).
- Prueba manual con datos reales (base local desechable, no Supabase): `23.132.164.73`,
  C2 de AsyncRAT en ThreatFox y 0 pulses en OTX → `asyncrat` (respaldada por ThreatFox),
  20 técnicas, confianza media, análisis de IA generado (Groq) citando `E-TF`, `E-VT` y
  `E-OTX`.
