# Fase 8b — Corte por legitimidad (falsos positivos en benignos)

Fecha: 2026-10-13. Rama `feat/metrics`. Viene de la Fase 8 (`fase-08-evaluacion.md`), donde se
cumplieron 7 de 8 umbrales. El que falló: **5 de 14 benignos con entidad (35,7 %)**, con un
umbral de ≤ 10 %.

## Diagnóstico

Las respuestas en caché de esos 5 casos ya traían una señal de legitimidad que NEXO veía pero
no usaba para decidir:

| Benigno | Atribuido a | Señal ignorada |
|---|---|---|
| 208.67.222.222 | qakbot | OTX `validation`: whitelist |
| github.com | shai-hulud | OTX: whitelist, false_positive |
| cloudflare.com | cobalt strike | OTX: whitelist |
| `putty.exe` | connectwise | VirusTotal: 1 de ~70 motores |
| `plink.exe` | sliver | VirusTotal: 0 de ~70 motores |

`detectar_contradicciones` ya marcaba `lista_blanca` y `vt_limpio`, pero solo bajaba la
confianza del informe; la etapa (a) atribuía igual. Además, la lista blanca solo contaba si no
había pulses enfocados (`benigno_conocido`), y por eso cloudflare.com, con 10 pulses, no la
activaba. En la muestra de maliciosos ninguno trae lista blanca de OTX, y todo hash malicioso que
VirusTotal conoce tiene 35 o más detecciones.

## Regla

`app/correlation/service.py::motivo_legitimidad(tipo, detalle, fuentes)`. La etapa (a) **no
atribuye** en dos casos:

1. **OTX tiene el indicador en lista blanca** (`validation[].source` ∈ {whitelist,
   false_positive}), haya o no pulses.
2. **Hash que VirusTotal analizó y no llega a "malicioso"**: menos de `UMBRAL_MALICIOSO` = 5
   motores.
   - Solo hashes: en una IP o un dominio, 0 detecciones es una señal débil, porque los C2 nuevos
     suelen tenerlo.
   - Un hash que VirusTotal no conoce no se toca.

Efectos:

- **Correlación:** `/correlate` y `GET /indicators/{id}` devuelven `resuelto: false` con
  `motivo`, el texto que explica el corte. Cuando hay entidad, `motivo` va en `null`.
- **Informe:** la confianza del informe es `baja` y el motivo va primero.
- **LLM:** no se llama, porque no hay entidad.
- **Links viejos:** volver a correlacionar borra el link que haya quedado de una correlación
  anterior (`indicator_entity_link.delete_by_indicator`). Así las investigaciones que ya
  estaban en Supabase se corrigen con solo pulsar "Correlacionar".
- **Lotes:** heredan el corte, porque solo participan los miembros con entidad.
- **Frontend:** la cadena de evidencia muestra el motivo debajo de "Sin asociación"
  (`EvidenceChain.tsx`), y `types.ts` y `fixtures.ts` se actualizaron.

`LISTAS_BLANCAS_OTX` pasó de `providers/otx.py` a `correlation/service.py`, porque `otx.py` ya
importa de ahí y lo contrario sería una importación circular.

## Resultados

La regla se diseñó mirando los 14 benignos de la Fase 8, así que **la evidencia que cuenta es un
conjunto nuevo** que no se usó para diseñarla: `eval/dataset_validacion.csv`.

- **14 maliciosos de tipo IP o dominio**, C2 de ESET malware-ioc. Prueban que la lista blanca
  no mata detecciones reales: la muestra de la Fase 8 solo tenía hashes.
- **16 benignos**, a propósito con casos difíciles:
  - servicios legítimos que el malware abusa: discord, pastebin, dropbox,
    raw.githubusercontent, drive.google, anydesk, teamviewer y zoom;
  - 3 DNS públicos;
  - 5 hashes publicados por el fabricante: PuTTY `pageant` y `puttygen`, VLC, Notepad++ y Git
    for Windows.

"Antes" y "después" usan **la misma caché**: se capturó en vivo con el código anterior (base
`nexo_validacion`) y se repitió con la regla.

### Validación (conjunto nuevo)

| Métrica | Antes | Después | Umbral |
|---|---|---|---|
| **Falsos positivos en benignos** | 3/16 = 18,8 % (IC95 7–43 %) ❌ | **1/16 = 6,3 %** (IC95 1–28 %) ✅ | ≤ 10 % |
| Detección (maliciosos con evidencia) | 13/14 | 13/14 | ≥ 80 % ✅ |
| Atribuciones de maliciosos | 8 resueltas, 3 correctas | **iguales: ninguna se perdió** | — |
| P de técnicas | 0,41 | 0,55 | — |

- **Cortados:**
  - pastebin.com (era asyncrat): lista blanca de OTX, aunque ThreatFox tiene 19 registros;
  - el instalador de Notepad++ (era cobalt strike): VirusTotal 1 de 69.
- **Sigue fallando:** 149.112.112.112 (DNS secundario de Quad9) → brickstorm. OTX no lo tiene
  en lista blanca y la regla de VirusTotal no aplica a IPs. Es el límite anticipado en el plan;
  no se ajustó la regla mirando este caso.
- **Significancia:** con 2 casos discordantes, McNemar exacto da p = 0,5. Sumando desarrollo y
  validación (30 benignos), los falsos positivos bajan de 8/30 = 26,7 % (IC95 14–44 %) a
  **1/30 = 3,3 %** (IC95 1–17 %). Los 7 casos discordantes van a favor: McNemar exacto
  p = 0,016.

### Desarrollo (los 37 de la Fase 8, misma caché)

| Métrica | Fase 8 | Con la regla | Umbral |
|---|---|---|---|
| **Falsos positivos** | 5/14 = 35,7 % ❌ | **0/14 = 0 %** ✅ | ≤ 10 % |
| Precisión / exhaustividad de atribución | 17/19 · 17/23 | 17/19 · 17/23 (sin cambios) | ✅ |
| F1 de técnicas | 0,70 | **0,82** (P 0,65 → 0,90) | ✅ |
| Tiempo con informe | mediana 2,96 s · p95 15,7 s | mediana 1,92 s · p95 19,6 s | ✅ |

**Con la regla, el conjunto de desarrollo cumple los 8 umbrales.** Solo confirma que la regla
hace lo que se diseñó.

En la corrida con informes, los 10 benignos con evidencia salen con confianza `baja` y el motivo
primero. Por ejemplo: "OTX lo lista como legítimo (whitelist): no se atribuye aunque otras
fuentes lo reporten". El p95 de 19,6 s se debe a que Groq respondió 429 (1000 tokens de salida
por minuto) y 10 de los 19 informes cayeron a Ollama. No tiene relación con la regla.

### Hallazgo aparte: la atribución de IoCs de red es débil

En el conjunto de validación, la atribución de IPs y dominios maliciosos es mala **con o sin la
regla**: 3 de 8 resueltos son correctos (precisión 37,5 %, por debajo del 70 %).

- Varias de las 5 "incorrectas" nombran el malware del grupo en vez del grupo:
  - plugx por Mustang Panda;
  - muddyviper por MuddyWater.
- Otras son errores reales:
  - zebrocy por Winter Vivern;
  - systembc por RansomHub;
  - plugx por GravityRAT.

Con la etiqueta estricta cuentan como errores. Los hashes (Fase 8, 17/19) funcionan mucho
mejor que la infraestructura de red. No es parte de esta fase: queda como hallazgo para una
mejora futura, que habría que validar con otro conjunto.

## Pruebas

- **Backend:** 403 passed (390 antes).
  - `test_correlation.py`: 9 casos parametrizados de `motivo_legitimidad`, más el borrado del
    link viejo y que la etapa (b) no se ejecute.
  - `test_multifuente.py`:
    - un hash con 1/70 en VirusTotal no se atribuye;
    - un hash malicioso en VirusTotal sí se atribuye;
    - la lista blanca corta lo que ThreatFox habría atribuido;
    - la contradicción `vt_limpio` se sigue probando con un dominio.
  - `test_consultas.py`: `GET` deduce el mismo corte sin `/correlate`.
  - **Mutación:** con `motivo_legitimidad` devolviendo siempre `None`, fallan 8 pruebas.
- **Frontend:** lint y typecheck en verde.
  - `EvidenceChain.test.tsx` cubre la nota con motivo y sin motivo; `App.test.tsx` cubre el
    8.8.8.8 con motivo.
  - 175 de 177 pruebas pasan. **Las 2 que fallan (`Batch.test.tsx`, botón "Escenario 4 ·
    SUNBURST") ya fallaban en `develop` antes de este cambio**: el commit `606f57c` cambió las
    etiquetas de los ejemplos del lote. Hay que corregirlas aparte; mientras tanto el CI
    (coverage) no pasa.

## Limitaciones

- **IPs y dominios legítimos sin lista blanca de OTX** (como el DNS de Quad9) siguen expuestos.
- **Muestras nuevas de malware** con menos de 5 detecciones en VirusTotal no se atribuyen hasta
  que los motores las detecten. Su evidencia se sigue mostrando, con confianza baja.
- **Dependencia de OTX:** la lista blanca es de OTX. Un dominio legítimo comprometido y usado
  como C2 no se atribuiría. Esto se eligió a propósito: el dominio en sí no es malicioso.
- **Muestra pequeña:** la mejora en el conjunto nuevo por sí solo no es significativa (p = 0,5).

## Reproducir

```bash
# Backend sobre la base de validación (con la caché de esta fase):
env DATABASE_URL=postgresql+psycopg://postgres:test@localhost:5433/nexo_validacion uvicorn app.main:app --port 8000
python -m eval.evaluar --dataset eval/dataset_validacion.csv

# Y sobre la de desarrollo:
env DATABASE_URL=postgresql+psycopg://postgres:test@localhost:5433/nexo_metricas uvicorn app.main:app --port 8000
python -m eval.evaluar

# Pruebas:
pytest tests/test_correlation.py tests/test_multifuente.py tests/test_consultas.py
```

Evidencia en `eval/resultados/`:

- `*-validacion-antes.json` y `*-validacion-despues.json`;
- `*-desarrollo-despues.json` y `*-desarrollo-despues-informe.json`;
- los `.log` de cada corrida.
