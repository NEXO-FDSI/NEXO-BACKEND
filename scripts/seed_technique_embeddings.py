"""Siembra en Chroma los embeddings del texto oficial de cada técnica ATT&CK. Idempotente.

    python -m scripts.seed_technique_embeddings
"""

import json

from app.ai_component.llm_client import embed_text
from app.ai_component.vectorstore import ChromaVectorStore
from app.core.config import settings

# Privadas a propósito: son las reglas de filtrado de la Etapa 6 y deben producir
# exactamente el mismo conjunto de técnicas que el índice de correlación. Duplicarlas aquí
# sería garantizar que se desincronicen. El índice no sirve: guarda nombre y táctica, no
# la description del objeto STIX.
from app.correlation.attck_loader import _attck_id, _tactica, _vivo


def main() -> None:
    with open(settings.ATTCK_STIX_PATH, encoding="utf-8") as f:
        objetos = json.load(f)["objects"]

    ids, embeddings, documents, metadatas = [], [], [], []
    for obj in objetos:
        if obj.get("type") != "attack-pattern" or not _vivo(obj):
            continue
        technique_id, tactica = _attck_id(obj), _tactica(obj)
        if not technique_id or not tactica or not obj.get("description"):
            continue

        texto = f"{obj['name']} ({tactica})\n\n{obj['description']}"
        ids.append(technique_id)
        embeddings.append(embed_text(texto))
        documents.append(texto)
        metadatas.append({"nombre": obj["name"], "tactica": tactica})

        if len(ids) % 100 == 0:
            print(f"  {len(ids)} embeddings generados...")

    ChromaVectorStore().upsert(ids, embeddings, documents, metadatas)
    print(f"técnicas indexadas: {len(ids)}")


if __name__ == "__main__":
    main()
