# Fase 1c — Eliminación de indicadores en cascada

Fecha: 2026-09-30. A pedido del usuario: eliminar un indicador desde la API o desde el
frontend, con eliminación en cascada de todos sus registros.

## Backend: `DELETE /indicators/{id}`

Una sola transacción, con borrados explícitos en orden (hijos primero). Las FK del esquema
no tienen `ON DELETE CASCADE`; hacerlo en la aplicación evita otra migración en Supabase y
permite devolver cuántas filas se borraron por tabla.

| Orden | Tabla | Criterio |
|---|---|---|
| 1 | `human_validation` | Validaciones de cualquier versión del informe del indicador |
| 2 | `reports` | Todas las versiones del informe |
| 3 | `indicator_entity_link` | Links de la etapa (a) |
| 4 | `enrichment_cache` | Caché de **todas** las fuentes (OTX, ThreatFox, VirusTotal) |
| 5 | `indicators` | El indicador |
| 6 | `entity_technique_link` | Solo de entidades que quedaron **huérfanas** |
| 7 | `entities` | Solo las huérfanas |

**No se borra:** el catálogo `techniques` (ATT&CK, compartido), ni las entidades y sus links
a técnicas si otro indicador todavía las usa.

Respuesta: `{"indicator_id", "valor", "eliminados": {tabla: filas}}`. 404 si no existe.
Queda un `WARNING` en el log con el valor y el conteo: borrar elimina el historial de
validación, que estaba diseñado como auditable, así que la constancia queda del lado del
servidor. Después, el mismo valor puede volver a registrarse.

Código: `eliminar_en_cascada` en `app/db/repositories/indicator.py` (solo `flush`) y el
endpoint en `app/api/indicators.py` (hace el `commit`), igual que el resto del proyecto.

## Frontend

En la cabecera del caso:
- **Eliminar** (peligro): confirmación explícita ("…se borran también sus informes, las
  validaciones de los analistas y la caché de las fuentes. Esta acción no se puede
  deshacer"), `DELETE /indicators/{id}`, se quita del historial y vuelve a la lista. Si
  falla, se muestra un aviso y el caso sigue ahí. Un 404 se trata como ya borrado.
- **Quitar del historial** (ahora con estilo secundario): solo lo quita del navegador,
  como antes.

Respeta el candado por indicador: no se borra mientras corre un paso sobre el mismo caso.

## Verificación

- Backend: **300 tests** (6 nuevos en `tests/test_eliminacion.py`): cascada completa con
  conteo exacto (2 informes, 2 validaciones, link, caché, entidad huérfana y sus 2 links),
  catálogo de técnicas intacto, entidad conservada si otro indicador la usa (y ese
  indicador conserva correlación e informes), indicador solo registrado, nuevo registro
  del mismo valor tras borrar, 404 y línea de auditoría en el log.
- Frontend: lint, typecheck y build en verde; **132 tests**, cobertura de ramas 91,8 %.
  Se agregó un caso de integración porque la acción es destructiva y la cobertura había
  quedado justo sobre el umbral del CI: cancelar no llama a la API, un fallo se informa y
  conserva el caso, eliminar vuelve a la lista y vacía el historial.
- Contra Supabase real, con un indicador de prueba creado para esto
  (`nexo-borrar-prueba.example`, #48): DELETE → 200 con conteo; GET y un segundo DELETE → 404.

## Ajuste: confirmación propia de la aplicación

A pedido del usuario se reemplazó `window.confirm` por `components/ui/ConfirmDialog.tsx`,
un `alertdialog` WAI-ARIA con la identidad visual de NEXO, usado tanto en **Eliminar** como
en **Quitar del historial**:

- **Eliminar** detalla qué se borra con los números del caso: versiones del informe (con
  su análisis y trazabilidad), decisiones de analistas ("se pierde ese historial de
  auditoría"), caché de las fuentes y el vínculo con la entidad (que solo se borra si
  queda huérfana). Remata con "Esta acción no se puede deshacer" y un botón sólido
  "Eliminar definitivamente". Si el backend falla, el error aparece **dentro del
  diálogo**, que sigue abierto para reintentar o cancelar.
- **Quitar del historial** (tono neutro) aclara que el indicador sigue en el backend y
  cómo volver a abrirlo.
- Accesibilidad: portal sobre fondo atenuado, foco inicial en **Cancelar** (la opción
  segura), foco atrapado con Tab y Shift+Tab, **Esc** cancela (salvo mientras borra) y al
  cerrar el foco vuelve al botón que lo abrió. jsdom no implementa
  `<dialog>.showModal()`, por eso el modal se resuelve a mano.
- Nuevo token `--color-on-danger` para el botón sólido: texto oscuro en tema oscuro
  (5,7:1; el blanco daba 3,4:1, bajo AA) y blanco en tema claro (5,6:1).

Verificación: lint, typecheck y build en verde; 132 tests (cobertura de ramas 91,5 %).
Los casos de integración de quitar y eliminar se adaptaron al diálogo y comprueban el
foco inicial, el ciclo de Tab, que Esc cancela sin llamar a la API y devuelve el foco, el
error dentro del diálogo y el reintento.

## Ajuste: una sola plataforma, sin "Quitar del historial"

A pedido del usuario (sin usuarios ni autenticación, el MVP es una sola plataforma):

- Se eliminó **Quitar del historial** (botón, diálogo y la acción `remove` del contexto):
  no aportaba valor si todo se ve desde el backend.
- Se eliminó la sección **"Registradas desde otros navegadores"** y su hook. Ahora hay
  **una sola lista** en Investigaciones y en el Panel.
- **El backend es la fuente de verdad** y `localStorage` es una caché. Al arrancar, `sync`
  hace `GET /indicators` (hasta 500), **depura** lo que ya no existe (acción `synced`;
  conserva ids mayores al máximo listado, por si se registraron mientras viajaba la
  consulta) y **carga lo que falta** con `GET /indicators/{id}`, de a 4 en paralelo. La
  lista muestra "Cargando N investigación(es) de la plataforma…" y, si el backend no
  responde, avisa y sigue con la caché.
- **Abrir un caso siempre lo refresca.** El refresco es una **fusión monotónica**: lo
  local (resultados de los POST) nunca retrocede ante un GET que salió antes; de lo
  remoto se suman informes y validaciones nuevos. Un 404 al cargar quita el caso.

`ponytail`: cargar los faltantes son N consultas `GET /indicators/{id}` (~1,5 s cada una
contra Supabase, de a 4). Si la plataforma crece, conviene un endpoint de listado con los
snapshots en lote.

Verificación: lint, typecheck y build en verde; 133 tests (cobertura de ramas 91,6 %).
El backend falso de los tests ahora pasa la *query string* a las rutas. Los tests
afectados se reescribieron para la lista unificada: carga desde el backend, depuración de
lo eliminado, 409 resuelto por búsqueda y aviso si la sincronización falla.
