# Fase 8 — Evaluación de NEXO

Fecha: 2026-10-12. Rama `feat/metrics`. La evaluación anterior de esta fase ya no estaba en
disco y se rehízo desde cero, con un solo script, un dataset nuevo y umbrales fijados en el
código (`eval/evaluar.py::UMBRALES`) **antes** de la primera corrida.

## Qué se evalúa

NEXO recibe un IoC y debe decir con evidencia **si es malicioso, a qué familia pertenece y qué
técnicas ATT&CK le corresponden**, sin inventar asociaciones para lo que es legítimo.

La atribución (entidad → técnicas) es **determinística** (`app/correlation/service.py`): el LLM
solo redacta el informe. Por eso las métricas de precisión miden las reglas de correlación, y
el LLM pesa en el tiempo de respuesta y en el informe, no en la atribución.

## Escenarios

| | Escenario | Entrada | Qué valida |
|---|---|---|---|
| A | **Ataque** | 23 hashes de 23 familias distintas presentes en ATT&CK 19.1, etiquetados por **ESET** ([malware-ioc](https://github.com/eset/malware-ioc), commit `705ead5`) | detección, atribución, técnicas y tiempo |
| B | **Control** | 14 benignos: 4 DNS públicos (8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222), 6 dominios (google, microsoft, github, wikipedia, cloudflare, apple) y 4 SHA-256 publicados por el fabricante (PuTTY 0.83 `putty.exe` y `plink.exe`; Node.js 22.20.0 `node.exe` y `.msi`) | falsos positivos |
| C | **Regresión sin red** | los 6 escenarios oficiales de la propuesta con respuestas reales congeladas (`tests/test_e2e_scenarios.py`) | que el pipeline completo funcione en la demo sin internet |

Para A se tomó un indicador por familia, con una regla fija:

- en el `README.adoc` de la carpeta, el primer hash cuya línea nombra la familia;
- si no hay ninguno, la primera línea de `samples.sha256`.

Las etiquetas no salen de OTX, ThreatFox ni VirusTotal. El dataset es `eval/dataset.csv`; la
columna `fuente` lleva el enlace de cada etiqueta.

## Métricas, método y umbrales

`eval/evaluar.py` recorre el dataset contra el backend corriendo. Por cada indicador llama a
`POST /indicators`, `/enrich`, `/correlate` y `/report`, y cronometra cada paso desde el cliente.

| Métrica | Cálculo | Umbral |
|---|---|---|
| Tasa de detección | maliciosos con `tiene_evidencia` / maliciosos | ≥ 80 % |
| Precisión de atribución | entidad correcta / maliciosos con entidad resuelta | ≥ 70 % |
| Exhaustividad de atribución | entidad correcta / maliciosos | ≥ 50 % |
| F1 de técnicas (micro) | técnicas propuestas vs. las que ATT&CK documenta para la familia real (mismo STIX); en un benigno, toda técnica propuesta es un FP | ≥ 0,60 |
| Tasa de falsos positivos | benignos con entidad resuelta / benignos | ≤ 10 % |
| Tiempo ingesta → informe | suma de los 4 pasos por indicador | mediana ≤ 30 s, p95 ≤ 60 s |
| Baseline sin reglas de NEXO | la familia más repetida en `malware_families` de **todos** los pulses de OTX (sin descartar volcados ni usar ThreatFox/VT), normalizada con el mismo índice ATT&CK | NEXO > baseline en precisión |
| Acuerdo humano | % de informes con última validación `aceptado` | se reporta, sin umbral |

Una entidad es correcta si coincide con la familia o con un alias de la etiqueta (columnas
`familia` y `alias`, p. ej. `astaroth|guildma`).

## Resultados

Corrida en vivo terminada el **2026-10-12 a las 23:50 UTC**, con las fuentes reales (OTX, ThreatFox y VirusTotal)
y el LLM real (Groq `qwen/qwen3.8-27b`, respaldo Ollama `qwen3:8b`). Evidencia:

- `eval/resultados/2026-10-12T235011Z-vivo.json`, con el detalle por indicador;
- `eval/resultados/corrida-vivo.log`.

| Métrica | Resultado | IC 95 % (Wilson) | Umbral | |
|---|---|---|---|---|
| Detección | **20/23 = 87,0 %** | 68–95 % | ≥ 80 % | ✅ |
| Precisión de atribución | **17/19 = 89,5 %** | 69–97 % | ≥ 70 % | ✅ |
| Exhaustividad de atribución | **17/23 = 73,9 %** | 54–87 % | ≥ 50 % | ✅ |
| Técnicas | VP 483 · FP 259 · FN 151 → P 0,651 · R 0,762 · **F1 0,702** | — | ≥ 0,60 | ✅ |
| Falsos positivos en benignos | **5/14 = 35,7 %** | 16–61 % | ≤ 10 % | ❌ |
| Tiempo ingesta → informe | mediana **2,96 s** · p95 **15,74 s** | — | ≤ 30 s / ≤ 60 s | ✅ |
| Baseline | NEXO 17/19 (89,5 %) vs. baseline **7/15 (46,7 %)** | 25–70 % | NEXO > baseline | ✅ |
| Acuerdo humano | sin validaciones todavía | — | — | pendiente |

**Se cumplen 7 de 8 umbrales. No se cumple el de falsos positivos.**

### Detalle

- **Aciertos (17):** andromeda, asyncrat, attor, metamorfo, macma, dynowiper, embargo, emotet,
  gelsemium, grandoreiro, gravityrat, astaroth, industroyer, keydnap, kobalos, lumma stealer y
  mispadu.
- **Errores de atribución (2):**
  - InvisiMole → `gamaredon group`. Confianza 0,6, solo etiquetas de OTX. El informe dice
    confianza **baja**. ESET documentó que ambos grupos colaboran, así que la etiqueta del pulse
    no es absurda, pero la atribución es incorrecta.
  - RansomHub → `systembc`. Confianza 0,9, por `malware_families` de un pulse de OTX. El informe
    dice confianza **media**.
- **Sin asociación (4):**
  - bandook, greyenergy y ramsay: ninguna fuente conoce el hash. El sistema lo dice y no
    inventa nada.
  - kasidet: VirusTotal tiene evidencia, pero su nombre de amenaza no resuelve a ninguna entidad
    de ATT&CK.
- **Falsos positivos (5/14):**

  | Indicador | Entidad | Confianza | Origen |
  |---|---|---|---|
  | 208.67.222.222 | qakbot | 0,6 | etiquetas de OTX |
  | github.com | shai-hulud | 0,9 | ThreatFox |
  | cloudflare.com | cobalt strike | 0,9 | OTX + ThreatFox |
  | `putty.exe` | connectwise | 0,6 | etiquetas de OTX |
  | `plink.exe` | sliver | 0,6 | etiquetas de OTX |

  Son infraestructura o herramientas legítimas que el malware usa o suplanta, y las fuentes de
  la comunidad las registran como IoC. Lo que mitiga el problema: **el informe de los 5 dice
  confianza `baja`**, mientras que en los 17 aciertos dice `alta` (9), `media` (8) o `baja` (2).
- **Baseline:** de sus 8 errores, 6 son familias equivocadas que salen de pulses masivos o
  mezclados: dcrat, tnx, ms4killer, `credit card`, spacecobra y edrkillshifter. Los otros 2
  (`grandoreiro - s0531`, `win32/invisimole`) son nombres que el índice ATT&CK no normaliza. Con
  una normalización más laxa el baseline subiría a 9/15 = 60 %, todavía por debajo de NEXO. En
  benignos el baseline también da 5 falsos positivos.
- **Tiempo:**
  - el LLM se llamó en 24 informes: 17 con Groq (mediana del paso `/report` 1,99 s) y 7 con el
    respaldo Ollama (12,42 s; máximo 18,2 s);
  - el respaldo entró porque Groq respondió 429 al superar su límite de 1000 tokens de salida
    por minuto (queda en `reports.metadatos.ia.intentos_fallidos`);
  - la mediana de los casos con LLM es 3,95 s y la de `/enrich`, con las fuentes en vivo, 0,88 s
    (máximo 5,5 s);
  - sin entidad no se llama al LLM, y por eso la mediana global es baja.

### Reproducibilidad comprobada

- **Repetición desde la caché** (`2026-10-12T235028Z-repeticion.json`): todas las métricas
  salvo los tiempos son **idénticas** a las de la corrida en vivo. Toma un segundo.
- **Corrida descartada:** hubo una primera corrida en vivo unos 13 minutos antes, sobre otra base.
  Su JSON se sobrescribió por un error del script: el nombre del archivo solo llevaba hasta los
  minutos. Ya está corregido. Dio exactamente las mismas métricas de atribución, FP y baseline,
  así que dos capturas independientes de las fuentes coincidieron.
- **Escenario C:** `pytest tests/test_e2e_scenarios.py` → 9 passed, sin red.
- **Suite completa:** 390 passed (388 antes, más los 2 de `tests/test_eval_metricas.py`).

## Limitaciones

- **Muestra pequeña** (23 + 14): los intervalos de confianza son anchos. Sirve como evidencia
  para la demo, no para generalizar.
- **Las etiquetas no son del todo independientes de las fuentes.** Los pulses de OTX suelen
  copiar los informes de los fabricantes, incluido ESET. La evaluación mide si NEXO **recupera
  y ordena** la atribución pública, no si descubre una nueva.
- **Las fuentes cambian.** Una base nueva puede dar otros números. La reproducible es la de
  esta corrida (base `nexo_metricas`).
- **Sin baseline "con y sin IA".** La comparación que proponía la propuesta no aplica a la
  atribución, porque no la hace el LLM. Se reemplazó por el baseline sin reglas.
- **El F1 de técnicas hereda la atribución:** con la entidad correcta, las técnicas también lo
  son (P = R = 1).
- **Acuerdo humano pendiente:** hace falta que el equipo valide los informes en la UI
  (abrir cada caso → Aceptar/Rechazar) y volver a correr el script.
- **Base efímera:** el contenedor de Postgres de tests no tiene volumen.
  `docker compose -f docker-compose.test.yml down` borra `nexo_metricas`. Si eso pasa, una
  corrida nueva en vivo vuelve a capturar y los números pueden variar.
- **Una base vieja sigue ahí:** `nexo_eval`, con los datos de la evaluación anterior, sigue en
  el contenedor. No se tocó.

## Cómo reproducirlo en la demo

Requisitos:

- `.env` con las claves de las tres fuentes y del LLM;
- el bundle STIX en `data/attck/`;
- Ollama corriendo (embeddings y respaldo del LLM).

```bash
docker compose -f docker-compose.test.yml up -d --wait

# Solo la primera vez (o si se borró el contenedor):
docker exec nexo-intel-backend-test-postgres-test-1 psql -U postgres -c "CREATE DATABASE nexo_metricas"
env DATABASE_URL=postgresql+psycopg://postgres:test@localhost:5433/nexo_metricas alembic upgrade head
env DATABASE_URL=postgresql+psycopg://postgres:test@localhost:5433/nexo_metricas python -m scripts.seed_techniques

# Backend sobre esa base (nunca Supabase):
env DATABASE_URL=postgresql+psycopg://postgres:test@localhost:5433/nexo_metricas uvicorn app.main:app --port 8000

# En otra terminal:
python -m eval.evaluar                      # repetición desde la caché: ~1 s, mismas métricas
python -m eval.evaluar --informe            # además genera informes y mide tiempos (LLM real)
python -m eval.evaluar --pausa 15 --informe # base vacía: captura en vivo (~12 min por el cupo de VT)

pytest tests/test_e2e_scenarios.py tests/test_eval_metricas.py   # escenario C y métricas, sin red
```

Cada corrida imprime la tabla con ✅/❌ y guarda `eval/resultados/<fecha>-<modo>.json`. Con el
backend corriendo, el frontend (`npm run dev`) muestra las 37 investigaciones de la base de
evaluación: así se pueden abrir en vivo un acierto (p. ej. Emotet), un caso sin evidencia
(bandook) y un falso positivo con confianza baja (cloudflare.com).

## Archivos

- `eval/dataset.csv`: 37 indicadores con su etiqueta y la fuente de la etiqueta.
- `eval/evaluar.py`: runner, métricas, baseline y umbrales. Solo stdlib más el índice ATT&CK.
- `eval/resultados/`: JSON y logs de la corrida en vivo y de la repetición.
- `tests/test_eval_metricas.py`: métricas y baseline sobre filas hechas a mano.
