"""Severidad y concordancia entre fuentes: determinísticas, sin LLM."""

import pytest

from app.reporting.severity import calcular_concordancia, calcular_severidad

EMOTET = {"resuelto": True, "entity": {"id": 1, "nombre": "emotet", "tipo": "malware"},
          "confianza": 0.9, "evidencia": "x", "tecnicas": []}
POR_TAGS = {**EMOTET, "confianza": 0.6}
SIN_ENTIDAD = {"resuelto": False, "entity": None, "confianza": None, "evidencia": None, "tecnicas": []}


def _fuente(nombre, estado="con_evidencia", **resumen):
    etiquetas = {"alienvault_otx": "AlienVault OTX", "threatfox": "ThreatFox", "virustotal": "VirusTotal"}
    base = {"tiene_evidencia": estado == "con_evidencia", "veredicto": "sin_evidencia", "familias": [],
            "detecciones": None}
    con_resumen = estado in ("con_evidencia", "sin_evidencia")
    return {"fuente": nombre, "etiqueta": etiquetas[nombre], "estado": estado,
            "resumen": {**base, **resumen} if con_resumen else None, "error": None}


def otx(pulses=0, veredicto="sin_evidencia", estado=None):
    return _fuente("alienvault_otx", estado or ("con_evidencia" if pulses else "sin_evidencia"),
                   veredicto=veredicto, detecciones={"pulses": pulses})


def vt(maliciosos=0, sospechosos=0, familias=(), estado=None):
    return _fuente("virustotal", estado or ("con_evidencia" if maliciosos or sospechosos else "sin_evidencia"),
                   familias=list(familias),
                   detecciones={"maliciosos": maliciosos, "sospechosos": sospechosos, "total": 70})


def tf(familias=(), estado=None):
    return _fuente("threatfox", estado or ("con_evidencia" if familias else "sin_evidencia"),
                   familias=list(familias))


@pytest.mark.parametrize("correlacion, fuentes, nivel", [
    # entidad fuerte + confirmación externa fuerte
    (EMOTET, [otx(3), vt(69)], "critica"),
    (EMOTET, [otx(3), tf(["Emotet"])], "critica"),
    # entidad fuerte sola, o señal externa fuerte sin entidad
    (EMOTET, [otx(3), vt(2)], "alta"),
    (SIN_ENTIDAD, [otx(0), vt(7)], "alta"),
    (SIN_ENTIDAD, [otx(0), tf(["Aisuru"])], "alta"),
    # señales débiles
    (POR_TAGS, [otx(1)], "media"),
    (SIN_ENTIDAD, [otx(0), vt(1)], "media"),
    (SIN_ENTIDAD, [otx(0), vt(0, sospechosos=1)], "media"),
    (SIN_ENTIDAD, [otx(4)], "media"),
    # sin señales
    (SIN_ENTIDAD, [otx(0, veredicto="benigno_conocido"), vt(0)], "benigno"),
    (SIN_ENTIDAD, [otx(0), vt(0), tf()], "baja"),
    # no poder verificar nunca es "baja"
    (SIN_ENTIDAD, [otx(0), vt(estado="limite_cuota")], "indeterminada"),
    (SIN_ENTIDAD, [otx(0), tf(estado="no_disponible")], "indeterminada"),
    (SIN_ENTIDAD, [otx(estado="omitido"), vt(estado="omitido"), tf(estado="omitido")], "indeterminada"),
    # la evidencia gana a la lista blanca
    (SIN_ENTIDAD, [otx(0, veredicto="benigno_conocido"), vt(3)], "media"),
    # una fuente no configurada no cuenta como fallo
    (SIN_ENTIDAD, [otx(0), vt(estado="no_configurado")], "baja"),
])
def test_tabla_de_severidad(correlacion, fuentes, nivel):
    resultado = calcular_severidad(correlacion, fuentes)
    assert resultado["nivel"] == nivel, resultado
    assert resultado["motivos"], "cada nivel debe explicar por qué"


def test_motivos_nombran_la_evidencia():
    motivos = calcular_severidad(EMOTET, [otx(3), vt(69), tf(["Emotet"])])["motivos"]
    assert motivos == [
        "asociado a emotet con confianza 0.9",
        "VirusTotal: 69 motores maliciosos, 0 sospechosos",
        "ThreatFox lo registra (Emotet)",
    ]


def test_indeterminada_nombra_las_fuentes_caidas():
    r = calcular_severidad(SIN_ENTIDAD, [otx(0), vt(estado="error"), tf(estado="limite_cuota")])
    assert r["motivos"] == ["no se pudo verificar en: VirusTotal, ThreatFox"]


# --- concordancia (índice sintético del conftest: emotet, alias geodo, apt-falso) ---


def _resultados(correlacion, fuentes, index):
    return {c["fuente"]: (c["resultado"], c["entidades"]) for c in calcular_concordancia(correlacion, fuentes, index)}


def test_concuerda_por_nombre_o_alias(attck_index):
    r = _resultados(EMOTET, [vt(60, familias=["Geodo"]), tf(["emotet"])], attck_index)
    assert r == {"virustotal": ("concuerda", ["emotet"]), "threatfox": ("concuerda", ["emotet"])}


def test_discrepa_si_la_fuente_apunta_a_otra_entidad(attck_index):
    """El caso real del SHA-1 de WannaCry: OTX sugería Cobalt Strike y VT decía wannacry."""
    r = _resultados(EMOTET, [vt(60, familias=["apt-falso"])], attck_index)
    assert r == {"virustotal": ("discrepa", ["apt-falso"])}


def test_sugiere_cuando_nexo_no_resolvio(attck_index):
    assert _resultados(SIN_ENTIDAD, [tf(["Emotet"])], attck_index) == {"threatfox": ("sugiere", ["emotet"])}


def test_familias_desconocidas_no_son_comparables_y_otx_no_se_compara(attck_index):
    r = _resultados(EMOTET, [otx(3), vt(60, familias=["trojan.generic"]), tf(estado="error")], attck_index)
    assert r == {"virustotal": ("no_comparable", [])}
