"""Salida estructurada del LLM y su depuración contra el contexto enviado.

El modelo solo redacta. Todo lo que cite algo fuera del contexto se descarta y se cuenta:
el analista ve cuántas afirmaciones se quitaron y por qué.
"""

import json
import re
from typing import Literal

from pydantic import BaseModel

TECNICA_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Topes de presentación: el modelo puede excederse; se recorta en vez de rechazar todo.
MAX_HALLAZGOS = 8
MAX_ITEMS = 5


class Hallazgo(BaseModel):
    afirmacion: str
    tipo: Literal["evidencia", "inferencia", "hipotesis"]
    fuentes: list[str] = []


class TecnicaDestacada(BaseModel):
    id: str
    motivo: str


class AnalisisIA(BaseModel):
    resumen: str
    hallazgos: list[Hallazgo] = []
    tecnicas_destacadas: list[TecnicaDestacada] = []
    investigacion_recomendada: list[str] = []
    limitaciones: list[str] = []
    informacion_faltante: list[str] = []


def parsear(texto: str) -> AnalisisIA:
    """JSON del modelo → AnalisisIA. Levanta ValueError si no es JSON válido o no cumple.

    Tolera un bloque ```json ... ``` alrededor, que algunos modelos agregan aunque se les
    pida JSON puro.
    """
    limpio = texto.strip()
    if limpio.startswith("```"):
        limpio = limpio.split("\n", 1)[-1].rsplit("```", 1)[0]
    return AnalisisIA.model_validate(json.loads(limpio))


def _tecnicas_ajenas(texto: str, tecnicas: set[str]) -> set[str]:
    return set(TECNICA_RE.findall(texto)) - tecnicas


def depurar(analisis: AnalisisIA, ids_contexto: set[str]) -> tuple[AnalisisIA | None, list[dict]]:
    """Quita lo que cite fuera del contexto. Devuelve (análisis depurado o None, descartes).

    Reglas:
    - cada id en `fuentes` debe estar en el contexto;
    - un hallazgo de tipo "evidencia" debe citar al menos un bloque de evidencia (E-*);
      una "inferencia", al menos un bloque cualquiera; una "hipótesis" puede no citar;
    - ningún texto puede nombrar una técnica T#### que no se haya enviado al modelo;
    - si no queda ni resumen ni hallazgos, no hay análisis (None).
    """
    tecnicas = {i for i in ids_contexto if TECNICA_RE.fullmatch(i)}
    descartes: list[dict] = []

    def descartar(seccion: str, texto: str, motivo: str) -> None:
        descartes.append({"seccion": seccion, "texto": texto[:300], "motivo": motivo})

    resumen = analisis.resumen.strip()
    if ajenas := _tecnicas_ajenas(resumen, tecnicas):
        descartar("resumen", resumen, f"menciona técnicas fuera del contexto: {', '.join(sorted(ajenas))}")
        resumen = ""

    hallazgos = []
    for h in analisis.hallazgos[:MAX_HALLAZGOS]:
        inexistentes = set(h.fuentes) - ids_contexto
        if inexistentes:
            descartar("hallazgos", h.afirmacion, f"cita fuentes inexistentes: {', '.join(sorted(inexistentes))}")
        elif ajenas := _tecnicas_ajenas(h.afirmacion, tecnicas):
            descartar("hallazgos", h.afirmacion, f"menciona técnicas fuera del contexto: {', '.join(sorted(ajenas))}")
        elif h.tipo == "evidencia" and not any(f.startswith("E-") for f in h.fuentes):
            descartar("hallazgos", h.afirmacion, "se presenta como evidencia sin citar una fuente de evidencia")
        elif h.tipo == "inferencia" and not h.fuentes:
            descartar("hallazgos", h.afirmacion, "inferencia sin ninguna fuente citada")
        else:
            hallazgos.append(h)

    destacadas = []
    for t in analisis.tecnicas_destacadas[:MAX_ITEMS]:
        if t.id not in tecnicas:
            descartar("tecnicas_destacadas", f"{t.id}: {t.motivo}", "técnica que no se envió al modelo")
        else:
            destacadas.append(t)

    def listas(seccion: str, items: list[str]) -> list[str]:
        salida = []
        for item in items[:MAX_ITEMS]:
            if ajenas := _tecnicas_ajenas(item, tecnicas):
                descartar(seccion, item, f"menciona técnicas fuera del contexto: {', '.join(sorted(ajenas))}")
            elif item.strip():
                salida.append(item.strip())
        return salida

    depurado = AnalisisIA(
        resumen=resumen,
        hallazgos=hallazgos,
        tecnicas_destacadas=destacadas,
        investigacion_recomendada=listas("investigacion_recomendada", analisis.investigacion_recomendada),
        limitaciones=listas("limitaciones", analisis.limitaciones),
        informacion_faltante=listas("informacion_faltante", analisis.informacion_faltante),
    )
    if not depurado.resumen and not depurado.hallazgos:
        return None, descartes
    return depurado, descartes
