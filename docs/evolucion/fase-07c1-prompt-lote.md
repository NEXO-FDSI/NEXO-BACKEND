# Fase 7c.1 — Ajuste del prompt del informe conjunto

Fecha: 2026-10-10. Corrige la observación que dejó la fase 7e (frontend
`docs/evolucion/fase-07e-informe-lote-ui.md`): el modelo atribuía la relación entre
indicadores a la entidad común, cuando NEXO la sustenta en las señales fuertes.

## Problema

En el escenario 4 (`2c4a…102e` + `ervsystem.com`), NEXO concluye "Relación demostrable entre I1
e I2" por **4 pulses enfocados de OTX compartidos**. La misma entidad (sunburst) es contexto: no
sube la confianza ni basta para agrupar (fase 7b). Pero el bloque `E-LOTE` ponía la frase
"Comparten la entidad atribuida sunburst…" justo después de la relación, sin decir qué la
sustentaba, y el modelo los unía en una relación causal.

## Cambio

Todo está en `app/ai_component/prompt_builder.py`; la correlación determinística no cambió.

- **`E-LOTE`** dice qué sustenta cada agrupación: "La sustentan solo sus señales fuertes: pulse
  compartido de AlienVault OTX (1 vínculo(s))". Cuenta por tipo de señal y no por vínculo, así
  que no crece con 190 vínculos: el tope de 16.000 caracteres del prompt se sigue cumpliendo.
  Si la agrupación también comparte entidad, agrega "compartir la entidad atribuida es solo
  contexto: no sustenta la agrupación". La confianza pasa a llamarse "confianza del vínculo".
- **`REGLAS_LOTE`** suma una regla: una agrupación se sustenta solo en las señales fuertes que
  nombra `E-LOTE`; nunca se dice que la relación existe "por" o "gracias a" la entidad, y la
  confianza de un vínculo no es la de la asociación de un indicador con su entidad.
- **`E-V#`:** la señal de misma entidad se rotula "(contexto: no sustenta la relación ni prueba
  la misma campaña)".

## Medición con Groq real

Se generaron tres informes conjuntos del escenario 4 antes y después del cambio, con
`qwen/qwen3.8-27b` y temperatura 0,2, sobre una base local desechable.

| Resumen del modelo | Antes | Después |
|---|---|---|
| Atribuye la relación a la entidad ("por compartir la entidad sunburst") | **2 de 3** | **0 de 3** |
| Atribuye la relación al pulse compartido | 1 de 3 (citando "vía vínculo E-V1") | **3 de 3** ("mediante pulse compartido de AlienVault OTX… se sustenta en señales fuertes, no en la entidad común") |
| Mezcla la confianza del vínculo con la de la asociación ("se asocian a sunburst con confianza media") | 1 de 3 | 0 de 3: separa la asociación 0.9 de la confianza media del vínculo |
| Descartes por citar fuera del contexto | 0 | 0 |

**Regresión de la abstención** (escenario 3, una corrida): "NEXO concluye que no existe relación
demostrable entre los tres indicadores del lote. Ningún par comparte pulse enfocado de OTX ni
infraestructura común". Además agrega, como inferencia, que las técnicas compartidas no
constituyen un vínculo. Sin descartes.

Tres corridas no son una estadística, pero el cambio de 2 de 3 a 0 de 3 coincide con lo que se
corrigió. La conclusión determinística, que va arriba en el informe, ya era correcta y no
cambió.

## Verificación

- `pytest`: 384 pruebas en verde. `test_informe_con_relacion_demostrable` ahora afirma el texto
  de sustento en `E-LOTE`, la nota de contexto y la regla nueva.
- La prueba del peor caso (20 URL largas, 190 vínculos en una sola agrupación) sigue por debajo
  de 16.000 caracteres.
