"""Fase 7b: correlación entre los indicadores de un lote.

Dos niveles: los escenarios 3 y 4 de la propuesta de punta a punta (respuestas reales de OTX
congeladas y subconjunto real de ATT&CK) y casos sintéticos sobre la función pura para cada
regla: señales, confianza por par, agrupaciones y abstención.
"""

import json
from pathlib import Path

import pytest

from app.correlation.attck_loader import AttckIndex
from app.correlation.lote import TACTIC_ORDER, correlacionar_lote
from app.correlation.service import MAX_INDICADORES_PULSE
from app.enrichment.providers.base import resumen

DATASET = Path(__file__).resolve().parents[1] / "data" / "test_dataset"
ESCENARIOS = json.loads((DATASET / "scenarios.json").read_text(encoding="utf-8"))
SUBSET = json.loads((DATASET / "attck_subset.json").read_text(encoding="utf-8"))
OTX_MOCK = "app.enrichment.client.fetch_reputation"


# --- Escenarios oficiales, por la API ---


@pytest.fixture
def attck_real() -> AttckIndex:
    return AttckIndex(**SUBSET)


@pytest.fixture
def lote(client, monkeypatch, attck_real):
    """Registra un lote, corre los pasos pedidos por indicador y devuelve su `correlacion`."""
    from app.api.correlation import get_attck_index
    from app.main import app

    app.dependency_overrides[get_attck_index] = lambda: attck_real
    respuestas = {c["indicator"]["valor"]: c["enrichment_response"]
                  for esc in ESCENARIOS.values() for c in esc.get("indicators", [esc])}
    monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key: respuestas[valor])

    def crear(indicadores: list[dict], pasos: list[tuple[str, ...]]):
        r = client.post("/batches", json={"indicadores": indicadores})
        assert r.status_code == 201, r.text
        miembros = [i["indicator_id"] for i in r.json()["items"] if i["indicator_id"]]
        for ind_id, sus_pasos in zip(miembros, pasos):
            for paso in sus_pasos:
                assert client.post(f"/indicators/{ind_id}/{paso}").status_code == 200
        return client.get(f"/batches/{r.json()['batch']['id']}").json()["correlacion"]

    return crear


AMBOS = ("enrich", "correlate")


def test_escenario_4_agrupa_por_pulses_compartidos(lote):
    casos = ESCENARIOS["scenario_4_misma_campana"]["indicators"]
    corr = lote([c["indicator"] for c in casos], [AMBOS, AMBOS])

    [v] = corr["vinculos"]
    assert (v["id"], v["a"], v["b"], v["confianza"]) == ("V1", "I1", "I2", "media")
    pulses, entidad = v["senales"]
    assert pulses["tipo"] == "pulse_compartido" and pulses["origen"] == "alienvault_otx"
    assert pulses["detalle"].startswith("4 pulse(s) enfocado(s)")
    assert all(p["indicadores"] <= MAX_INDICADORES_PULSE for p in pulses["pulses"])
    # La misma entidad acompaña, pero no sube la confianza: sale de esos mismos pulses.
    assert entidad["tipo"] == "misma_entidad" and entidad["fuerza"] == "contextual"
    assert entidad["detalle"].startswith("ambos se asocian a sunburst (malware): I1 con 0.9 vía AlienVault OTX")

    [a] = corr["agrupaciones"]
    assert (a["id"], a["indicadores"], a["vinculos"], a["confianza"]) == ("A1", ["I1", "I2"], ["V1"], "media")
    assert len(a["tecnicas_comunes"]) == len(SUBSET["entity_techniques"]["sunburst"]) == 36
    assert corr["conclusion"] == {
        "nivel": "relacion_demostrable",
        "texto": "Relación demostrable entre I1 y I2 (A1, confianza media). Comparten la entidad atribuida "
                 "sunburst, lo que no prueba que pertenezcan a la misma campaña.",
        "entidad_comun": ["sunburst"], "aislados": [], "no_participan": [],
    }
    assert corr["cobertura"]["nivel"] == "completa"


def test_escenario_3_sin_relacion_aunque_compartan_tecnicas(lote):
    esc = ESCENARIOS["scenario_3_multiples_tecnicas"]
    corr = lote([c["indicator"] for c in esc["indicators"]], [AMBOS] * 3)

    assert {i["entidad"]["nombre"] for i in corr["indicadores"]} == {"lazarus group", "remcos", "dridex"}
    assert corr["vinculos"] == [] and corr["agrupaciones"] == []
    assert corr["conclusion"]["nivel"] == "sin_relacion_demostrable"
    assert corr["conclusion"]["texto"] == (
        "Sin relación demostrable entre los indicadores. Ningún par comparte un pulse enfocado de OTX ni infraestructura."
    )
    # Cobertura conjunta en orden ATT&CK, con el solapamiento marcado... que no generó vínculos.
    tacticas = [g["tactica"].lower() for g in corr["cadena_ataque"]]
    assert len(tacticas) >= esc["expected"]["min_tacticas"]
    assert tacticas == sorted(tacticas, key=TACTIC_ORDER.index)
    compartidas = [t for g in corr["cadena_ataque"] for t in g["tecnicas"] if t["varias_entidades"]]
    assert compartidas and all(len(t["entidades"]) > 1 for t in compartidas)


def test_solo_participan_los_que_tienen_entidad(lote):
    sunburst = [c["indicator"] for c in ESCENARIOS["scenario_4_misma_campana"]["indicators"]]
    corr = lote(
        [*sunburst,
         ESCENARIOS["scenario_5_indicador_benigno"]["indicator"],  # 8.8.8.8: benigno conocido
         ESCENARIOS["scenario_1_amenaza_conocida"]["indicator"],  # WannaCry: enriquecido, sin /correlate
         {"tipo": "ip", "valor": "45.33.32.156"},  # solo registrado
         {"tipo": "ip", "valor": "999.0.0.1"}],  # descartado: no es miembro ni tiene ref
        [AMBOS, AMBOS, AMBOS, ("enrich",), ()],
    )

    estados = {i["ref"]: (i["estado"], (i["severidad"] or {}).get("nivel")) for i in corr["indicadores"]}
    assert estados == {
        "I1": ("participa", "alta"), "I2": ("participa", "alta"), "I3": ("sin_entidad", "benigno"),
        "I4": ("sin_correlacionar", None), "I5": ("sin_enriquecer", None),
    }
    assert [(v["a"], v["b"]) for v in corr["vinculos"]] == [("I1", "I2")]
    assert corr["conclusion"]["no_participan"] == ["I3", "I4", "I5"]
    cobertura = corr["cobertura"]
    assert (cobertura["nivel"], cobertura["validos"], cobertura["participan"], cobertura["descartados"]) == (
        "parcial", 5, 2, 1)
    assert (cobertura["sin_entidad"], cobertura["sin_correlacionar"], cobertura["sin_enriquecer"]) == (
        ["I3"], ["I4"], ["I5"])
    # En tests solo OTX está configurada: ThreatFox y VirusTotal no aparecen en la cobertura.
    assert [(f["fuente"], f["verificados"]) for f in cobertura["fuentes"]] == [("alienvault_otx", ["I1", "I2", "I3", "I4"])]


# --- Reglas, sobre la función pura (índice sintético del conftest) ---

ENTITY_ID = {"emotet": 1, "apt-falso": 2, "ambigua": 3}


def _lote(index: AttckIndex, *casos: tuple) -> dict:
    """casos: (tipo, valor, entidad | None, {pulse_id: indicator_count}). Arma ítems e
    investigaciones con la forma de BatchItemRead y de construir()."""
    items, investigaciones = [], []
    for n, (tipo, valor, entidad, pulses) in enumerate(casos, 1):
        items.append({"posicion": n, "entrada": valor, "tipo": tipo, "ingesta": "creado", "indicator_id": n,
                      "valor": valor, "motivo": None})
        fuentes = [{"fuente": "alienvault_otx", "etiqueta": "AlienVault OTX", "estado": "con_evidencia", "error": None,
                    "resumen": resumen(tiene_evidencia=True, veredicto="malicioso", familias=[entidad] if entidad else [])}]
        correlation = {
            "indicator_id": n, "resuelto": entidad is not None,
            "entity": {"id": ENTITY_ID[entidad], "nombre": entidad, "tipo": index.entity_type[entidad]} if entidad else None,
            "confianza": 0.9 if entidad else None, "evidencia": "sintética",
            "fuentes": ["alienvault_otx"] if entidad else [],
            "tecnicas": [{"id": t, **index.techniques[t]} for t in index.entity_techniques.get(entidad, [])],
        }
        investigaciones.append({
            "enrichment": {"cobertura": "completa", "fuentes": fuentes, "detalle": {"pulse_info": {
                "pulses": [{"id": pid, "name": f"pulse {pid}", "indicator_count": cuenta} for pid, cuenta in pulses.items()]}}},
            "correlation": correlation,
        })
    return correlacionar_lote(items, investigaciones, index)


def test_solo_la_misma_entidad_es_baja_y_no_agrupa(attck_index):
    corr = _lote(attck_index, ("ip", "80.0.0.1", "emotet", {}), ("ip", "80.0.0.2", "emotet", {}))

    [v] = corr["vinculos"]
    assert v["confianza"] == "baja" and [s["tipo"] for s in v["senales"]] == ["misma_entidad"]
    assert corr["agrupaciones"] == []
    assert corr["conclusion"]["nivel"] == "sin_relacion_demostrable"
    assert corr["conclusion"]["texto"].startswith("Sin relación demostrable entre los indicadores.")
    assert "Comparten la entidad atribuida emotet, lo que no prueba" in corr["conclusion"]["texto"]
    assert corr["conclusion"]["aislados"] == ["I1", "I2"]


def test_pulse_mas_infraestructura_es_alta(attck_index):
    corr = _lote(attck_index,
                 ("url", "http://evil.example/x", "emotet", {"p1": 10}),
                 ("domain", "evil.example", "emotet", {"p1": 10}))

    [v] = corr["vinculos"]
    assert [s["tipo"] for s in v["senales"]] == ["pulse_compartido", "infraestructura", "misma_entidad"]
    assert v["senales"][1]["detalle"] == "I1 está alojado en I2 (evil.example)"
    assert v["confianza"] == "alta"
    assert corr["agrupaciones"][0]["confianza"] == "alta"


@pytest.mark.parametrize("hijo,padre,detalle", [
    (("domain", "a.evil.example"), ("domain", "evil.example"), "I1 (a.evil.example) es subdominio de I2 (evil.example)"),
    (("url", "http://203.0.113.5:8080/x"), ("ip", "203.0.113.5"), "I1 está alojado en I2 (203.0.113.5)"),
    (("url", "http://[2001:db8::1]/x"), ("ip", "2001:db8::1"), "I1 está alojado en I2 (2001:db8::1)"),
])
def test_infraestructura_sola_agrupa_con_confianza_media(attck_index, hijo, padre, detalle):
    corr = _lote(attck_index, (*hijo, "emotet", {}), (*padre, "apt-falso", {}))

    [v] = corr["vinculos"]
    assert [(s["tipo"], s["detalle"]) for s in v["senales"]] == [("infraestructura", detalle)]
    assert v["confianza"] == "media" and corr["conclusion"]["nivel"] == "relacion_demostrable"


def test_dos_url_en_el_mismo_host_solo_se_agrupan_a_traves_del_dominio(attck_index):
    url_a = ("url", "https://docs.example/a", "emotet", {})
    url_b = ("url", "https://docs.example/b", "apt-falso", {})
    # Solas no: el host puede ser una plataforma compartida.
    assert _lote(attck_index, url_a, url_b)["vinculos"] == []

    corr = _lote(attck_index, url_a, url_b, ("domain", "docs.example", "ambigua", {}))
    assert [(v["a"], v["b"]) for v in corr["vinculos"]] == [("I1", "I3"), ("I2", "I3")]
    assert corr["agrupaciones"][0]["indicadores"] == ["I1", "I2", "I3"]


def test_las_tecnicas_compartidas_no_son_senal(attck_index):
    # emotet (T9001, T9002) y ambigua (T9001, T9003) comparten T9001.
    corr = _lote(attck_index, ("ip", "81.0.0.1", "emotet", {}), ("ip", "81.0.0.2", "ambigua", {}))

    assert corr["vinculos"] == [] and corr["conclusion"]["nivel"] == "sin_relacion_demostrable"
    cadena = {g["tactica"]: g["tecnicas"] for g in corr["cadena_ataque"]}
    assert list(cadena) == ["Initial Access", "Execution", "Persistence"]  # orden ATT&CK
    [t9001] = cadena["Initial Access"]
    assert (t9001["id"], t9001["indicadores"], t9001["entidades"], t9001["varias_entidades"]) == (
        "T9001", ["I1", "I2"], ["emotet", "ambigua"], True)
    assert cadena["Execution"][0]["varias_entidades"] is False


@pytest.mark.parametrize("cuenta,vinculos", [(MAX_INDICADORES_PULSE, 1), (MAX_INDICADORES_PULSE + 1, 0)])
def test_un_volcado_masivo_no_cuenta_como_pulse_compartido(attck_index, cuenta, vinculos):
    corr = _lote(attck_index, ("ip", "82.0.0.1", "emotet", {"vol": cuenta}), ("ip", "82.0.0.2", "apt-falso", {"vol": cuenta}))
    assert len(corr["vinculos"]) == vinculos


def test_la_agrupacion_vale_lo_que_su_vinculo_mas_debil(attck_index):
    corr = _lote(attck_index,
                 ("url", "http://x.example/p", "emotet", {"p1": 10}),
                 ("domain", "x.example", "emotet", {"p1": 10, "p2": 10}),
                 ("ip", "198.51.100.7", "apt-falso", {"p2": 10}))

    assert [(v["id"], v["a"], v["b"], v["confianza"]) for v in corr["vinculos"]] == [
        ("V1", "I1", "I2", "alta"), ("V2", "I2", "I3", "media")]
    [a] = corr["agrupaciones"]
    assert (a["indicadores"], a["vinculos"], a["confianza"]) == (["I1", "I2", "I3"], ["V1", "V2"], "media")
    assert a["tecnicas_comunes"] == []  # emotet y apt-falso no comparten técnicas


def test_la_entidad_ambigua_lo_declara(attck_index):
    corr = _lote(attck_index, ("ip", "83.0.0.1", "ambigua", {}), ("ip", "83.0.0.2", "ambigua", {}))
    assert "(nombre ambiguo en ATT&CK: grupo, malware — técnicas fusionadas)" in corr["vinculos"][0]["senales"][0]["detalle"]


def test_con_menos_de_dos_participantes_no_hay_relaciones_que_evaluar(attck_index):
    corr = _lote(attck_index, ("ip", "84.0.0.1", "emotet", {"p": 10}), ("ip", "84.0.0.2", None, {"p": 10}))

    # Comparten un pulse, pero el segundo no tiene entidad: no participa (invariante 4).
    assert corr["vinculos"] == []
    assert corr["conclusion"]["texto"] == (
        "Sin relación demostrable entre los indicadores. Menos de dos indicadores con entidad resuelta: "
        "no hay relaciones que evaluar."
    )
    assert corr["conclusion"]["no_participan"] == ["I2"]
