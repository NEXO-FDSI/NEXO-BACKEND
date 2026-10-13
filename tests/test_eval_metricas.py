"""Métricas de la evaluación (eval/evaluar.py): lógica pura, sin BD ni red."""

from eval.evaluar import baseline, metricas, veredicto


def _fila(clase, familia="", alias="", entidad=None, tecnicas=(), reales=(), evidencia=True,
          base=None, informe_s=None, validaciones=()):
    tiempos = {"ingesta": 0.1, "enrich": 1.0, "correlate": 0.1}
    if informe_s is not None:
        tiempos["report"] = informe_s
    return {"clase": clase, "familia": familia, "alias": alias, "entidad": entidad,
            "tecnicas": list(tecnicas), "tecnicas_reales": list(reales), "tiene_evidencia": evidencia,
            "entidad_baseline": base, "tiempos_s": tiempos, "validaciones": list(validaciones)}


def test_metricas_sobre_cuatro_filas():
    filas = [
        # acierto por alias; el baseline se equivoca
        _fila("malicioso", "astaroth", "guildma", entidad="Guildma", tecnicas=["T1", "T2"],
              reales=["T1", "T2"], base="emotet", informe_s=8.9, validaciones=["rechazado", "aceptado"]),
        # atribución equivocada: sus técnicas cuentan como FP y las reales como FN
        _fila("malicioso", "emotet", entidad="trickbot", tecnicas=["T3"], reales=["T1", "T4"],
              base="emotet", informe_s=18.9),
        # sin evidencia: no resuelve
        _fila("malicioso", "kobalos", reales=["T5"], evidencia=False),
        # benigno con entidad: falso positivo
        _fila("benigno", entidad="mirai", tecnicas=["T6"], validaciones=["rechazado"]),
    ]
    m = metricas(filas)

    assert m["deteccion"] == round(2 / 3, 4)
    assert (m["atribuciones_correctas"], m["maliciosos_resueltos"]) == (1, 2)
    assert m["precision_atribucion"] == 0.5
    assert m["exhaustividad_atribucion"] == round(1 / 3, 4)
    assert m["tecnicas_vp_fp_fn"] == [2, 2, 3]  # VP T1,T2 · FP T3,T6 · FN T1,T4,T5
    assert m["f1_tecnicas"] == round(2 * 0.5 * 0.4 / 0.9, 4)
    assert m["tasa_falsos_positivos"] == 1.0
    assert (m["baseline_correctas"], m["baseline_resueltos"]) == (1, 2)
    assert m["tiempo_mediana_s"] == 15.1  # (10.1 + 20.1) / 2
    assert m["acuerdo_humano"] == 0.5  # cuenta la última decisión de cada informe

    v = veredicto(m)
    assert v["precision_atribucion"] is False and v["tiempo_mediana_s"] is True
    assert v["supera_baseline"] is False  # 0.5 no supera 0.5


def test_baseline_cuenta_todos_los_pulses_incluso_volcados():
    detalle = {"pulse_info": {"pulses": [
        {"indicator_count": 5, "malware_families": [{"display_name": "WannaCry"}]},
        {"indicator_count": 2_000_000, "malware_families": ["Cobalt Strike"]},
        {"indicator_count": 9_000_000, "malware_families": [{"display_name": "Cobalt Strike"}]},
    ]}}
    assert baseline(detalle, str.lower) == "cobalt strike"
    assert baseline({}, str.lower) is None
