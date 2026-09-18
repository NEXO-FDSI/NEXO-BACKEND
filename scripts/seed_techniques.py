"""Siembra la tabla techniques con el catálogo ATT&CK. Idempotente.

    python -m scripts.seed_techniques
"""

from sqlalchemy import select

from app.core.config import settings
from app.correlation.attck_loader import load_attck_index
from app.db.database import SessionLocal
from app.db.models import Technique
from app.db.repositories import technique_repository


def main() -> None:
    index = load_attck_index(settings.ATTCK_STIX_PATH)
    print(f"índice cargado: {len(index.techniques)} técnicas vivas")

    with SessionLocal() as db:
        # Un SELECT en vez de una llamada get() por técnica: mismo get-or-create,
        # 1 roundtrip contra el pooler de Supabase en vez de ~700.
        existentes = set(db.scalars(select(Technique.id)))
        faltantes = [t for t in index.techniques if t not in existentes]

        for technique_id in faltantes:
            technique_repository.create(db, {"id": technique_id, **index.techniques[technique_id]})
        db.commit()

    print(f"ya existían: {len(existentes)} | insertadas: {len(faltantes)}")


if __name__ == "__main__":
    main()
