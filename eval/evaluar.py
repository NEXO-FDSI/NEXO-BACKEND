"""Evaluación de NEXO contra el backend corriendo (Fase 8).

Por cada fila de eval/dataset.csv: POST /indicators → /enrich → /correlate (→ /report con
--informe), cronometrando cada paso. Compara la entidad resuelta con la etiqueta (ESET
malware-ioc o fabricante, nunca OTX/ThreatFox/VirusTotal) y calcula las métricas de
docs/evolucion/fase-08-evaluacion.md frente a sus umbrales.

    python -m eval.evaluar --pausa 15 --informe     # primera corrida, fuentes en vivo
    python -m eval.evaluar                          # repetición: las fuentes salen de la caché

Solo stdlib + el índice ATT&CK del backend (para las técnicas de la familia real y para
normalizar el baseline).
"""

import argparse
import csv
import json
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
STIX = RAIZ.parent / "data" / "attck" / "enterprise-attack-19.1.json"

# Fijados antes de la primera corrida (ver el informe de la fase). (comparador, valor)
UMBRALES = {
    "deteccion": (">=", 0.80),
    "precision_atribucion": (">=", 0.70),
    "exhaustividad_atribucion": (">=", 0.50),
    "f1_tecnicas": (">=", 0.60),
    "tasa_falsos_positivos": ("<=", 0.10),
    "tiempo_mediana_s": ("<=", 30.0),
    "tiempo_p95_s": ("<=", 60.0),
}


class Api:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def __call__(self, metodo: str, ruta: str, cuerpo: dict | None = None, timeout: int = 150):
        datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
        req = urllib.request.Request(self.base + ruta, data=datos, method=metodo,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")


def _cronometrado(api: Api, metodo: str, ruta: str, cuerpo: dict | None = None):
    inicio = time.perf_counter()
    estado, cuerpo = api(metodo, ruta, cuerpo)
    return estado, cuerpo, round(time.perf_counter() - inicio, 3)


def baseline(detalle: dict, normalizar) -> str | None:
    """Sin las reglas de NEXO: la familia más repetida en `malware_families` de TODOS los
    pulses de OTX (también los volcados masivos), sin ThreatFox ni VirusTotal. Empate → la
    primera en aparecer (Counter conserva el orden de inserción)."""
    votos = Counter()
    for pulse in (detalle.get("pulse_info") or {}).get("pulses") or []:
        for familia in pulse.get("malware_families") or []:
            nombre = familia.get("display_name") if isinstance(familia, dict) else familia
            if nombre:
                votos[normalizar(nombre)] += 1
    return votos.most_common(1)[0][0] if votos else None


def evaluar_fila(api: Api, fila: dict, informe: bool) -> dict:
    tipo, valor = fila["tipo"], fila["valor"]
    r = {**fila, "tiempos_s": {}, "error": None}

    estado, cuerpo, r["tiempos_s"]["ingesta"] = _cronometrado(api, "POST", "/indicators",
                                                              {"tipo": tipo, "valor": valor})
    if estado == 409:  # ya registrado en esta base: se reutiliza
        q = urllib.parse.urlencode({"tipo": tipo, "valor": valor})
        cuerpo = api("GET", f"/indicators?{q}")[1][0]
    elif estado != 201:
        r["error"] = f"ingesta {estado}: {cuerpo}"
        return r
    iid = r["indicator_id"] = cuerpo["id"]

    estado, cuerpo, r["tiempos_s"]["enrich"] = _cronometrado(api, "POST", f"/indicators/{iid}/enrich")
    if estado != 200:
        r["error"] = f"enrich {estado}: {cuerpo}"
        return r
    r["tiene_evidencia"] = cuerpo["tiene_evidencia"]
    r["fuentes"] = {f["fuente"]: f["estado"] for f in cuerpo["fuentes"]}

    estado, cuerpo, r["tiempos_s"]["correlate"] = _cronometrado(api, "POST", f"/indicators/{iid}/correlate")
    if estado != 200:
        r["error"] = f"correlate {estado}: {cuerpo}"
        return r
    r["entidad"] = (cuerpo["entity"] or {}).get("nombre")
    r["confianza_entidad"] = cuerpo["confianza"]
    r["tecnicas"] = [t["id"] for t in cuerpo["tecnicas"]]

    if informe:
        estado, cuerpo, r["tiempos_s"]["report"] = _cronometrado(api, "POST", f"/indicators/{iid}/report")
        if estado != 201:
            # No invalida la atribución (ya medida); solo deja fuera este tiempo.
            r["error_informe"] = f"report {estado}: {cuerpo}"
            del r["tiempos_s"]["report"]
        else:
            meta = cuerpo.get("metadatos") or {}
            r["report_id"] = cuerpo["id"]
            r["confianza_informe"] = meta.get("confianza")
            r["ia"] = {k: (meta.get("ia") or {}).get(k) for k in ("estado", "proveedor", "modelo", "latencia_ms")}

    snapshot = api("GET", f"/indicators/{iid}")[1]
    r["detalle_otx"] = (snapshot.get("enrichment") or {}).get("detalle") or {}
    r["validaciones"] = [v["decision"] for v in snapshot.get("validations") or []]
    return r


def _correcta(entidad: str | None, fila: dict) -> bool:
    nombres = {fila["familia"], *filter(None, fila["alias"].split("|"))}
    return entidad is not None and entidad.lower() in nombres


def _razon(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def metricas(filas: list[dict]) -> dict:
    """Pura: cada fila trae clase, familia, alias, tiene_evidencia, entidad, tecnicas,
    tecnicas_reales, entidad_baseline, tiempos_s y validaciones."""
    mal = [f for f in filas if f["clase"] == "malicioso"]
    ben = [f for f in filas if f["clase"] == "benigno"]
    resueltos = [f for f in mal if f.get("entidad")]
    correctos = [f for f in resueltos if _correcta(f["entidad"], f)]
    base_resueltos = [f for f in mal if f.get("entidad_baseline")]
    base_correctos = [f for f in base_resueltos if _correcta(f["entidad_baseline"], f)]

    # Micro sobre todas las filas: en un benigno toda técnica propuesta es un falso positivo.
    tp = fp = fn = 0
    for f in filas:
        propuestas, reales = set(f.get("tecnicas") or []), set(f.get("tecnicas_reales") or [])
        tp, fp, fn = tp + len(propuestas & reales), fp + len(propuestas - reales), fn + len(reales - propuestas)
    p, r = _razon(tp, tp + fp), _razon(tp, tp + fn)

    m = {
        "n_maliciosos": len(mal), "n_benignos": len(ben),
        "deteccion": _razon(sum(bool(f.get("tiene_evidencia")) for f in mal), len(mal)),
        "maliciosos_resueltos": len(resueltos), "atribuciones_correctas": len(correctos),
        "precision_atribucion": _razon(len(correctos), len(resueltos)),
        "exhaustividad_atribucion": _razon(len(correctos), len(mal)),
        "tecnicas_vp_fp_fn": [tp, fp, fn],
        "precision_tecnicas": p, "exhaustividad_tecnicas": r,
        "f1_tecnicas": round(2 * p * r / (p + r), 4) if p and r else 0.0,
        "benignos_con_entidad": sum(bool(f.get("entidad")) for f in ben),
        "benignos_con_evidencia": sum(bool(f.get("tiene_evidencia")) for f in ben),
        "tasa_falsos_positivos": _razon(sum(bool(f.get("entidad")) for f in ben), len(ben)),
        "baseline_resueltos": len(base_resueltos), "baseline_correctas": len(base_correctos),
        "baseline_precision_atribucion": _razon(len(base_correctos), len(base_resueltos)),
        "baseline_exhaustividad_atribucion": _razon(len(base_correctos), len(mal)),
        "baseline_benignos_con_entidad": sum(bool(f.get("entidad_baseline")) for f in ben),
    }

    totales = [sum(f["tiempos_s"].values()) for f in filas if "report" in f.get("tiempos_s", {})]
    if totales:
        m["tiempo_mediana_s"] = round(statistics.median(totales), 2)
        m["tiempo_p95_s"] = round(statistics.quantiles(totales, n=20, method="inclusive")[18], 2) \
            if len(totales) > 1 else totales[0]

    # Observaciones sin umbral: el LLM solo se llama con entidad resuelta, y el informe de un
    # falso positivo puede avisarlo con su propio nivel de confianza.
    con_llm = [sum(f["tiempos_s"].values()) for f in filas
               if (f.get("ia") or {}).get("estado") == "generado" and "report" in f["tiempos_s"]]
    m["tiempo_mediana_con_llm_s"] = round(statistics.median(con_llm), 2) if con_llm else None
    m["confianza_informe_falsos_positivos"] = [
        (f.get("confianza_informe") or {}).get("nivel") for f in ben if f.get("entidad")]

    decisiones = [f["validaciones"][-1] for f in filas if f.get("validaciones")]
    m["validados"] = len(decisiones)
    m["acuerdo_humano"] = _razon(decisiones.count("aceptado"), len(decisiones))
    return m


def veredicto(m: dict) -> dict[str, bool | None]:
    """True/False por umbral; None si la métrica no se midió."""
    out = {}
    for nombre, (op, umbral) in UMBRALES.items():
        v = m.get(nombre)
        out[nombre] = None if v is None else (v >= umbral if op == ">=" else v <= umbral)
    pb, pn = m.get("baseline_precision_atribucion"), m.get("precision_atribucion")
    out["supera_baseline"] = None if pn is None else pn > (pb or 0)
    return out


def imprimir(m: dict, v: dict) -> None:
    marca = {True: "✅", False: "❌", None: "—"}
    print(f"\nMaliciosos: {m['n_maliciosos']}  ·  Benignos: {m['n_benignos']}\n")
    for nombre, (op, umbral) in UMBRALES.items():
        print(f"  {marca[v[nombre]]} {nombre:<28} {str(m.get(nombre)):>8}   (umbral {op} {umbral})")
    print(f"  {marca[v['supera_baseline']]} {'supera_baseline':<28} "
          f"{m['precision_atribucion']} vs {m['baseline_precision_atribucion']}")
    print(f"\n  atribución: {m['atribuciones_correctas']}/{m['maliciosos_resueltos']} correctas de "
          f"{m['n_maliciosos']}; baseline {m['baseline_correctas']}/{m['baseline_resueltos']}")
    print(f"  técnicas VP/FP/FN: {m['tecnicas_vp_fp_fn']}  P={m['precision_tecnicas']} "
          f"R={m['exhaustividad_tecnicas']}")
    print(f"  benignos con evidencia: {m['benignos_con_evidencia']}; con entidad: "
          f"{m['benignos_con_entidad']} (baseline {m['baseline_benignos_con_entidad']})")
    print(f"  mediana con LLM: {m['tiempo_mediana_con_llm_s']} s; confianza del informe en los "
          f"falsos positivos: {m['confianza_informe_falsos_positivos']}")
    print(f"  acuerdo humano: {m['acuerdo_humano']} sobre {m['validados']} validados")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--dataset", default=str(RAIZ / "dataset.csv"))
    ap.add_argument("--informe", action="store_true", help="genera el informe (LLM) y mide el tiempo total")
    ap.add_argument("--pausa", type=float, default=0, help="segundos entre indicadores (cupo de VirusTotal/Groq)")
    args = ap.parse_args()

    from app.correlation.attck_loader import find_entity, load_attck_index
    index = load_attck_index(str(STIX))
    api = Api(args.api)
    filas = list(csv.DictReader(open(args.dataset, encoding="utf-8")))

    resultados = []
    for i, fila in enumerate(filas, 1):
        r = evaluar_fila(api, fila, args.informe)
        r["tecnicas_reales"] = index.entity_techniques.get(fila["familia"], []) if fila["familia"] else []
        r["entidad_baseline"] = baseline(r.pop("detalle_otx", {}), lambda n: find_entity(index, n) or n.lower())
        resultados.append(r)
        print(f"[{i:>2}/{len(filas)}] {fila['clase']:<9} {fila['valor'][:24]:<24} → "
              f"{r.get('entidad') or r['error'] or 'sin asociación'}  "
              f"(esperada: {fila['familia'] or '—'}; {sum(r['tiempos_s'].values()):.1f} s)", flush=True)
        if args.pausa and i < len(filas):
            time.sleep(args.pausa)

    errores = [r for r in resultados if r["error"]]
    m = metricas([r for r in resultados if not r["error"]])
    v = veredicto(m)
    imprimir(m, v)
    if errores:
        print(f"\n  ⚠ {len(errores)} indicadores con error (excluidos de las métricas)")

    modo = "vivo" if args.informe else "repeticion"
    salida = RAIZ / "resultados" / f"{datetime.now(timezone.utc):%Y-%m-%dT%H%M%SZ}-{modo}.json"
    salida.parent.mkdir(exist_ok=True)
    salida.write_text(json.dumps({
        "fecha_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "api": args.api, "informe": args.informe, "umbrales": UMBRALES,
        "metricas": m, "veredicto": v, "filas": resultados,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nResultados: {salida.relative_to(RAIZ.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
