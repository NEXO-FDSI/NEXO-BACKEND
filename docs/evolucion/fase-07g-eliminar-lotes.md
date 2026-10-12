# Fase 7g — Eliminar lotes

Fecha: 2026-10-10. Pedido del usuario: poder eliminar un lote igual que un indicador. El plan de
la Fase 7 lo había dejado fuera del MVP (§5, P9). La 7f, validación por vínculo, sigue fuera
por decisión del usuario.

## Decisión de diseño

**Borrar un lote no borra sus indicadores.** Cada indicador es una investigación propia: puede
estar en otros lotes, haberse analizado solo, o tener informes y validaciones individuales. Se
borra solo lo que pertenece al lote: las entradas que se pegaron (`batch_items`), los informes
conjuntos (todas las versiones) y sus validaciones. El diálogo de confirmación lo dice.

## Backend

- **`DELETE /batches/{id}`** (`app/api/batches.py`) copia el patrón de `DELETE /indicators/{id}`:
  - una sola transacción;
  - responde `{batch_id, nombre, eliminados}` con las filas por tabla;
  - deja un **WARNING** en el log ("lote #1 (Lote para eliminar) eliminado en cascada: …"),
    porque se pierde el historial de validación;
  - **404** si el lote no existe.
- **`app/db/repositories/batch.py::eliminar_lote_en_cascada`**: como las FK no tienen
  `ON DELETE CASCADE`, borra en orden: `batch_validation` → `batch_reports` → `batch_items` →
  `batches`. Solo hace flush; el commit es del endpoint.
- **Sin migración:** las tablas ya existían.

Pruebas en `tests/test_eliminacion.py` (+4):

- Borra informes, validaciones y entradas sin tocar los indicadores: siguen como investigaciones
  completas, con su entidad, y otro lote que comparte un indicador queda intacto.
- Un lote sin informes.
- 404.
- WARNING en el log.

`pytest`: **388 pruebas en verde**, frente a 384.

## Frontend

- **"Eliminar" en la cabecera del lote** (`BatchPage.tsx`). Está deshabilitado mientras se
  analiza o se genera un informe.
- **Diálogo de confirmación,** el mismo `ConfirmDialog` y los mismos estilos que el de un
  indicador. Lista las versiones del informe conjunto, las decisiones ("se pierde ese
  historial de auditoría") y las entradas que se pegaron, y aclara que los indicadores **no** se
  eliminan.
- **Al confirmar,** vuelve a la lista de lotes. Si el backend falla, el diálogo sigue abierto con
  el error y se puede reintentar. Si el lote ya no existía (404), el resultado es el mismo.
- **Acción `deleteBatch`** en `pipelineActions` y `nexoApi.deleteBatch`.
- **Pruebas** (+2):
  - la acción: ok, 404 y caída;
  - el flujo en la UI: consecuencias, cancelar sin enviar nada, error y reintento, navegación, y
    que no se llama a `DELETE /indicators`.

  Quedan **177 pruebas** y cobertura de 97,6 %. Lint, typecheck y build en verde.

## Verificación en vivo

Se probó contra el backend real, sobre una base local desechable (no Supabase), por la
interfaz.

1. Se creó un lote de 2 indicadores y 1 entrada inválida, con informe conjunto (relación
   demostrable) y una decisión.
2. Se eliminó: "Eliminar" → diálogo → "Eliminar definitivamente". El navegador volvió a
   `#/lotes`, que mostró "Aún no hay lotes".
3. `GET /batches/1` respondió 404. Log: `{'batch_validation': 1, 'batch_reports': 1,
   'batch_items': 3, 'batches': 1}`.
4. Los dos indicadores siguieron en `GET /indicators/{id}` con su entidad (sunburst).

Captura del diálogo (frontend): `docs/evolucion/capturas/f7g-eliminar-lote-oscuro.png`.

## Observación

Los indicadores que el lote creó conservan `fuente = "Lote #<id>"` después de borrarlo. Es una
etiqueta histórica de dónde se registraron: no apunta a nada.
