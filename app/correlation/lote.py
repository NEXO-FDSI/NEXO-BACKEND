"""Correlación entre los indicadores de un lote (Fase 7b). Lógica pura: no escribe ni sale a
la red; trabaja sobre las investigaciones que arma `construir()`.

Reglas (plan de la Fase 7, §2.6):
- Solo participan los indicadores con entidad resuelta (invariante 4). Un benigno nunca
  resuelve, así que también queda fuera; el resto aparece con su estado.
- Señales fuertes: un pulse enfocado de OTX que lista a ambos, o la misma infraestructura
  (una URL o un subdominio sobre un dominio o IP que el analista incluyó en el lote).
  Señal contextual: la misma entidad atribuida.
- Las técnicas y tácticas NUNCA son señal: son las documentadas en ATT&CK para la entidad,
  no comportamiento observado. `_vinculos` no las lee; solo `_cadena_ataque` las usa, como
  cobertura conjunta.
- Confianza de un par: alta con señales fuertes de 2+ orígenes distintos, media con uno,
  baja con solo la misma entidad. La misma entidad no suma: suele salir de los mismos pulses
  que ya cuentan como compartidos (sería contar dos veces la misma evidencia).
- Agrupaciones: componentes conexos de los vínculos de confianza alta o media.
"""

import ipaddress
from collections import Counter
from itertools import combinations
from urllib.parse import urlsplit

from app.correlation.attck_loader import AttckIndex
from app.correlation.service import MAX_INDICADORES_PULSE
from app.enrichment.service import FALLIDOS, RESPONDIERON
from app.reporting.severity import _lista, evaluar

# Orden de la matriz Enterprise ATT&CK 19.1, espejo de src/domain/attck.ts del frontend.
TACTIC_ORDER = (
    "reconnaissance", "resource development", "initial access", "execution", "persistence",
    "privilege escalation", "stealth", "defense impairment", "credential access", "discovery",
    "lateral movement", "collection", "command and control", "exfiltration", "impact",
)
PULSES_LISTADOS = 5  # por señal; el detalle dice cuántos son en total
SIN_RELACION = "Sin relación demostrable entre los indicadores."


def correlacionar_lote(items: list[dict], investigaciones: list[dict], index: AttckIndex) -> dict:
    """items: los del lote en orden (forma de BatchItemRead); investigaciones: las de
    construir() para los ítems con indicador, en ese mismo orden."""
    miembros = _miembros(items, investigaciones, index)
    participan = [m for m in miembros if m["estado"] == "participa"]
    vinculos = _vinculos(participan, index)
    agrupaciones = _agrupaciones(vinculos, participan)
    return {
        "indicadores": [{k: v for k, v in m.items() if not k.startswith("_")} for m in miembros],
        "vinculos": vinculos,
        "agrupaciones": agrupaciones,
        "conclusion": _conclusion(miembros, agrupaciones),
        "cobertura": _cobertura(items, miembros),
        "cadena_ataque": _cadena_ataque(participan),
    }


def _host(tipo: str, valor: str) -> str | None:
    """Host de un indicador, para comparar infraestructura. None para un hash."""
    if tipo == "url":
        valor = urlsplit(valor).hostname
    elif tipo not in ("domain", "ip"):
        return None
    if not valor:
        return None
    try:
        return str(ipaddress.ip_address(valor))  # IPv6 en forma canónica, como la guarda NEXO
    except ValueError:
        return valor


def _miembros(items: list[dict], investigaciones: list[dict], index: AttckIndex) -> list[dict]:
    con_indicador = [i for i in items if i["indicator_id"] is not None]
    miembros = []
    for n, (item, inv) in enumerate(zip(con_indicador, investigaciones, strict=True), 1):
        enrichment, correlation = inv["enrichment"], inv["correlation"]
        fuentes = enrichment["fuentes"] if enrichment else []
        if enrichment is None:
            estado = "sin_enriquecer"
        elif correlation is None:
            estado = "sin_correlacionar"  # resolvería, pero /correlate no se ejecutó
        else:
            estado = "participa" if correlation["resuelto"] else "sin_entidad"
        resuelto = estado == "participa"
        evaluacion = evaluar(correlation, fuentes, index) if correlation else {}
        pulses = ((enrichment or {}).get("detalle") or {}).get("pulse_info", {}).get("pulses") or []
        miembros.append({
            "ref": f"I{n}",
            "indicator_id": item["indicator_id"],
            "tipo": item["tipo"],
            "valor": item["valor"],
            "ingesta": item["ingesta"],
            "estado": estado,
            "entidad": correlation["entity"] if resuelto else None,
            "asociacion": correlation["confianza"] if resuelto else None,
            "severidad": evaluacion.get("severidad"),
            "confianza": evaluacion.get("confianza"),
            "contradicciones": evaluacion.get("contradicciones", []),
            "cobertura": enrichment["cobertura"] if enrichment else None,
            "fuentes": [{k: f[k] for k in ("fuente", "etiqueta", "estado")} for f in fuentes],
            # Privados (no salen en la respuesta): lo que usan las señales y la cadena.
            "_pulses": {
                p["id"]: p for p in pulses
                if isinstance(p, dict) and p.get("id") and (p.get("indicator_count") or 0) <= MAX_INDICADORES_PULSE
            },
            "_host": _host(item["tipo"], item["valor"]),
            "_correlacion": correlation,
        })
    return miembros


def _infraestructura(x: dict, y: dict) -> dict | None:
    """Señal si uno de los dos ES el dominio o la IP que aloja al otro. Dos URL en el mismo
    host no se vinculan solas: el host puede ser una plataforma compartida (docs.google.com);
    se agrupan a través del dominio si el analista lo incluyó en el lote."""
    for hijo, padre in ((x, y), (y, x)):
        if padre["tipo"] not in ("domain", "ip") or not hijo["_host"]:
            continue
        if hijo["_host"] == padre["_host"]:
            detalle = f"{hijo['ref']} está alojado en {padre['ref']} ({padre['_host']})"
        elif padre["tipo"] == "domain" and hijo["_host"].endswith("." + padre["_host"]):
            detalle = f"{hijo['ref']} ({hijo['_host']}) es subdominio de {padre['ref']} ({padre['_host']})"
        else:
            continue
        return {"tipo": "infraestructura", "fuerza": "fuerte", "origen": "estructura", "detalle": detalle}
    return None


def _misma_entidad(x: dict, y: dict, index: AttckIndex) -> dict:
    entidad = x["entidad"]

    def asociacion(m: dict) -> str:
        etiqueta = {f["fuente"]: f["etiqueta"] for f in m["fuentes"]}
        fuentes = [etiqueta.get(f, f) for f in m["_correlacion"]["fuentes"]]
        return f"{m['ref']} con {m['asociacion']}" + (f" vía {_lista(fuentes)}" if fuentes else "")

    detalle = f"ambos se asocian a {entidad['nombre']} ({entidad['tipo']}): {asociacion(x)}; {asociacion(y)}"
    if entidad["nombre"] in index.ambiguous:
        detalle += f" (nombre ambiguo en ATT&CK: {', '.join(index.ambiguous[entidad['nombre']])} — técnicas fusionadas)"
    return {"tipo": "misma_entidad", "fuerza": "contextual", "origen": "correlacion_nexo", "detalle": detalle,
            "entity_id": entidad["id"]}


def _confianza_par(senales: list[dict]) -> str:
    origenes = {s["origen"] for s in senales if s["fuerza"] == "fuerte"}
    return "alta" if len(origenes) >= 2 else "media" if origenes else "baja"


def _vinculos(participan: list[dict], index: AttckIndex) -> list[dict]:
    senales: dict[tuple[int, int], list[dict]] = {}  # (i, j) con i < j: posiciones en participan

    # 1) Pulses enfocados compartidos: índice invertido, O(total de pulses) y no O(N² · P).
    por_pulse: dict[str, list[int]] = {}
    for i, m in enumerate(participan):
        for pid in m["_pulses"]:
            por_pulse.setdefault(pid, []).append(i)
    compartidos: dict[tuple[int, int], list[str]] = {}
    for pid, posiciones in por_pulse.items():
        for par in combinations(posiciones, 2):
            compartidos.setdefault(par, []).append(pid)
    for (i, j), pids in compartidos.items():
        pulses = [participan[i]["_pulses"][pid] for pid in pids]
        senales.setdefault((i, j), []).append({
            "tipo": "pulse_compartido", "fuerza": "fuerte", "origen": "alienvault_otx",
            "detalle": f"{len(pids)} pulse(s) enfocado(s) de AlienVault OTX listan ambos indicadores",
            # El nombre es texto libre de terceros: se muestra en la UI, nunca va al LLM.
            "pulses": [
                {"id": p["id"], "nombre": p.get("name"), "indicadores": p.get("indicator_count")}
                for p in pulses[:PULSES_LISTADOS]
            ],
        })

    # 2) Infraestructura, solo con los valores normalizados.
    for (i, x), (j, y) in combinations(enumerate(participan), 2):
        if senal := _infraestructura(x, y):
            senales.setdefault((i, j), []).append(senal)

    # 3) Misma entidad atribuida.
    por_entidad: dict[int, list[int]] = {}
    for i, m in enumerate(participan):
        por_entidad.setdefault(m["entidad"]["id"], []).append(i)
    for posiciones in por_entidad.values():
        for i, j in combinations(posiciones, 2):
            senales.setdefault((i, j), []).append(_misma_entidad(participan[i], participan[j], index))

    return [
        {"id": f"V{n}", "a": participan[i]["ref"], "b": participan[j]["ref"], "confianza": _confianza_par(s),
         "senales": s}
        for n, ((i, j), s) in enumerate(sorted(senales.items()), 1)
    ]


def _agrupaciones(vinculos: list[dict], participan: list[dict]) -> list[dict]:
    """Componentes conexos de los vínculos alta/media (unión-búsqueda; con 20 no hace falta más)."""
    padre = {m["ref"]: m["ref"] for m in participan}

    def raiz(ref: str) -> str:
        while padre[ref] != ref:
            ref = padre[ref]
        return ref

    fuertes = [v for v in vinculos if v["confianza"] != "baja"]
    for v in fuertes:
        padre[raiz(v["b"])] = raiz(v["a"])
    componentes: dict[str, list[dict]] = {}
    for m in participan:
        componentes.setdefault(raiz(m["ref"]), []).append(m)

    agrupaciones = []
    for ms in componentes.values():
        if len(ms) < 2:
            continue
        refs = [m["ref"] for m in ms]
        propios = [v for v in fuertes if v["a"] in refs]
        comunes = set.intersection(*({t["id"] for t in m["_correlacion"]["tecnicas"]} for m in ms))
        agrupaciones.append({
            "id": f"A{len(agrupaciones) + 1}",
            "indicadores": refs,
            "vinculos": [v["id"] for v in propios],
            # La del vínculo más débil: una agrupación no es más segura que su eslabón peor.
            "confianza": "media" if any(v["confianza"] == "media" for v in propios) else "alta",
            "tecnicas_comunes": sorted(comunes),
        })
    return agrupaciones


def _conclusion(miembros: list[dict], agrupaciones: list[dict]) -> dict:
    participan = [m for m in miembros if m["estado"] == "participa"]
    agrupados = {ref for a in agrupaciones for ref in a["indicadores"]}
    entidad_comun = sorted(n for n, veces in Counter(m["entidad"]["nombre"] for m in participan).items() if veces > 1)
    if agrupaciones:
        nivel = "relacion_demostrable"
        texto = " ".join(
            f"Relación demostrable entre {_lista(a['indicadores'])} ({a['id']}, confianza {a['confianza']})."
            for a in agrupaciones
        )
    else:
        nivel = "sin_relacion_demostrable"
        texto = SIN_RELACION + (
            " Menos de dos indicadores con entidad resuelta: no hay relaciones que evaluar."
            if len(participan) < 2
            else " Ningún par comparte un pulse enfocado de OTX ni infraestructura."
        )
    if entidad_comun:
        texto += (
            f" Comparten la entidad atribuida {_lista(entidad_comun)}, lo que no prueba que pertenezcan "
            "a la misma campaña."
        )
    return {
        "nivel": nivel,
        "texto": texto,
        "entidad_comun": entidad_comun,
        "aislados": [m["ref"] for m in participan if m["ref"] not in agrupados],
        "no_participan": [m["ref"] for m in miembros if m["estado"] != "participa"],
    }


def _cobertura(items: list[dict], miembros: list[dict]) -> dict:
    def con_estado(estado: str) -> list[str]:
        return [m["ref"] for m in miembros if m["estado"] == estado]

    fuentes: dict[str, dict] = {}
    for m in miembros:
        for f in m["fuentes"]:
            dato = fuentes.setdefault(
                f["fuente"], {"fuente": f["fuente"], "etiqueta": f["etiqueta"], "verificados": [], "sin_verificar": []}
            )
            if f["estado"] in RESPONDIERON:
                dato["verificados"].append(m["ref"])
            elif f["estado"] in FALLIDOS:  # no se pudo verificar: no es "sin evidencia"
                dato["sin_verificar"].append(m["ref"])
    fuentes_usadas = [d for d in fuentes.values() if d["verificados"] or d["sin_verificar"]]
    pendientes = con_estado("sin_correlacionar") + con_estado("sin_enriquecer")
    return {
        "nivel": "parcial" if pendientes or any(d["sin_verificar"] for d in fuentes_usadas) else "completa",
        "validos": len(miembros),
        "participan": len(con_estado("participa")),
        "descartados": sum(1 for i in items if i["ingesta"] in ("invalido", "duplicado")),
        "sin_entidad": con_estado("sin_entidad"),
        "sin_correlacionar": con_estado("sin_correlacionar"),
        "sin_enriquecer": con_estado("sin_enriquecer"),
        "fuentes": fuentes_usadas,
    }


def _rango(tactica: str) -> int:
    clave = tactica.lower()
    return TACTIC_ORDER.index(clave) if clave in TACTIC_ORDER else len(TACTIC_ORDER)


def _cadena_ataque(participan: list[dict]) -> list[dict]:
    """Cobertura conjunta: técnicas documentadas para las entidades del lote, por táctica en
    orden ATT&CK. `varias_entidades` marca solapamiento entre entidades distintas, que NO
    prueba relación."""
    tecnicas: dict[str, dict] = {}
    for m in participan:
        for t in m["_correlacion"]["tecnicas"]:
            dato = tecnicas.setdefault(
                t["id"], {"id": t["id"], "nombre": t["nombre"], "tactica": t["tactica"], "indicadores": [], "entidades": []}
            )
            dato["indicadores"].append(m["ref"])
            if m["entidad"]["nombre"] not in dato["entidades"]:
                dato["entidades"].append(m["entidad"]["nombre"])

    por_tactica: dict[str, list[dict]] = {}
    for t in sorted(tecnicas.values(), key=lambda t: t["id"]):
        tactica = t.pop("tactica")
        por_tactica.setdefault(tactica, []).append({**t, "varias_entidades": len(t["entidades"]) > 1})
    return [
        {"tactica": tactica, "tecnicas": lista}
        for tactica, lista in sorted(por_tactica.items(), key=lambda kv: (_rango(kv[0]), kv[0]))
    ]
