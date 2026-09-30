# Fase 3 — IA multi-perfil: Groq primario + Ollama de respaldo

Fecha: 2026-09-30. Orden del sprint: F0 → F1 → **F3** → F2 → F4 (la F3 va antes que la F2
porque solo depende de F1 y quita el mayor riesgo de la demo: la latencia del LLM).

## Decisión de diseño

Ollama, Groq y OpenRouter exponen el mismo `/v1/chat/completions` compatible con OpenAI y
el backend ya usaba ese SDK. Un proveedor es, por tanto, un **perfil de configuración**
(`Perfil`: etiqueta, URL, clave, modelo, `reasoning_effort`, timeout), no una clase por
proveedor. `generate_analysis` recorre `[primario, respaldo]` y devuelve el primero que
responda. Una jerarquía `AIProvider` se justificará solo si llega un proveedor que no hable
este protocolo.

## Selección del modelo (medido con el prompt real de WannaCry, 6 097 caracteres)

| Perfil | `reasoning_effort` | Latencia | Resultado |
|---|---|---:|---|
| Groq `qwen/qwen3.8-27b` | `none` | **0,9 s** | ✅ elegido como primario |
| Groq `qwen/qwen3.8-27b` | (sin enviar) | 1,4 s | ✅ |
| Groq `openai/gpt-oss-120b` | `none` | — | ❌ 400 *"reasoning_effort must be one of low, medium, high"*: confirma D1 |
| Groq `openai/gpt-oss-120b` | `low` | 1,2 s | ✅ |
| Ollama `qwen3:8b` (GPU local) | `none` | 3,8–13,9 s (en frío) | ✅ elegido como respaldo |

Catálogo consultado en vivo con la clave del proyecto (`GET /models`). `qwen/qwen3.8-27b`
es de la misma familia que el modelo local, así que el prompt se comporta igual en ambos.
Observación útil para la F4: en una corrida, `qwen3:8b` describió T1489 (*Service Stop*)
como "detección de servicios", una alucinación que la validación de citas debe atrapar.

## Cambios

| Hallazgo | Cambio | Archivos |
|---|---|---|
| D1 · `reasoning_effort` fijo | Configurable por perfil; vacío = no se envía | `app/ai_component/llm_client.py`, `app/core/config.py` |
| Proveedor único | Perfiles `LLM_*` (primario) y `LLM_FALLBACK_*` (respaldo, opcional); `LLMServiceError.intentos` deja el rastro de cada perfil probado | `llm_client.py`, `config.py` |
| D3 · embeddings atados al chat | `EMBEDDING_BASE_URL` / `EMBEDDING_API_KEY` propios: la siembra sigue en Ollama con el chat en Groq | `llm_client.py`, `config.py` |
| Trazabilidad | `generate_analysis` → `(texto, meta)` con proveedor, modelo, latencia, tokens e intentos fallidos. El informe agrega una línea de autoría bajo "Análisis" e indica si se usó el respaldo | `app/ai_component/service.py`, `app/reporting/{service,template}.py` |
| Docker | `docker-compose.yml` sobrescribía `LLM_BASE_URL` con el Ollama del host, lo que habría mandado el modelo y la clave de Groq a Ollama. Ahora sobrescribe `LLM_FALLBACK_BASE_URL` y `EMBEDDING_BASE_URL` | `docker-compose.yml` |
| Logs con cabeceras | El SDK de `openai` 3.x usa `httpx2`, no `httpx`: la guarda de la F1 no lo cubría. Ahora ambos quedan fijos en ≥ INFO | `app/main.py` |
| Configuración | `.env` local apuntado a Groq + respaldo Ollama; `.env.example` documenta los perfiles (Groq, solo local, OpenRouter) | `.env` (no versionado), `.env.example` |

Timeouts: primario 20 s + respaldo 60 s = 80 s en el peor caso, por debajo de los 120 s
que el frontend espera en `/report`.

## Verificación

- `pytest`: **209 passed** (199 de la F1 + 10 nuevos). Se ajustaron los stubs que parchean
  `generate_analysis` para devolver `(texto, meta)`; ninguna expectativa de negocio cambió.
- Tests nuevos (`tests/test_llm_client.py` y `tests/test_hardening.py`):
  - primario responde y el respaldo no se toca;
  - primario cae → responde el respaldo y `meta.intentos_fallidos` lo registra;
  - ambos caen → `LLMServiceError` con los dos intentos;
  - sin respaldo configurado → solo se prueba el primario;
  - `reasoning_effort` se envía solo si está configurado (`none` y vacío);
  - respuesta vacía = fallo;
  - embeddings usan su propio endpoint aunque el chat apunte a Groq;
  - línea de autoría con y sin respaldo;
  - `httpx` y `httpx2` con nivel propio ≥ INFO (mutación verificada: falla sin `httpx2`).
- Prueba real, sin BD (índice ATT&CK real + Chroma real + escenario 1):
  1. `.env` real → *groq · qwen/qwen3.8-27b · 1185 ms*.
  2. Clave de Groq inválida → 401 registrado → *ollama · qwen3:8b · 3830 ms (respaldo: groq no respondió)*.
  3. Ambos caídos → `(None, None)`: el informe sale sin análisis y el log explica ambos fallos.
  4. `embed_text` → 768 dimensiones contra Ollama con el chat en Groq.
