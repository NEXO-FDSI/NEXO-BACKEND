"""Acceso al vector store. Único módulo del proyecto que importa chromadb.

La interfaz existe porque el spec de la etapa la exige: cambiar Chroma (local) por
un servicio cloud no debe tocar service.py ni prompt_builder.py.
"""

from typing import Protocol

import chromadb

from app.core.config import settings

COLECCION = "attck_techniques"


class VectorStore(Protocol):
    def upsert(
        self,
        ids: list[str],
        embeddings: list[list[float]],
        documents: list[str],
        metadatas: list[dict],
    ) -> None: ...

    def get_by_ids(self, ids: list[str]) -> dict[str, dict]:
        """{id: {"document": str, "metadata": dict}} solo para los ids que existan.

        Los ids no encontrados se omiten del resultado, sin lanzar excepción.
        """
        ...


class ChromaVectorStore:
    """Implementación sobre un Chroma persistente en disco."""

    def __init__(self, persist_dir: str | None = None):
        client = chromadb.PersistentClient(path=persist_dir or settings.CHROMA_PERSIST_DIR)
        self._coleccion = client.get_or_create_collection(COLECCION)

    def upsert(
        self,
        ids: list[str],
        embeddings: list[list[float]],
        documents: list[str],
        metadatas: list[dict],
    ) -> None:
        # upsert y no add: reinsertar el mismo id sobrescribe, así la siembra es idempotente.
        self._coleccion.upsert(
            ids=ids, embeddings=embeddings, documents=documents, metadatas=metadatas
        )

    def get_by_ids(self, ids: list[str]) -> dict[str, dict]:
        if not ids:
            return {}
        # collection.get() ya omite por sí solo los ids inexistentes, y su include por
        # defecto trae documents + metadatas.
        resultado = self._coleccion.get(ids=ids)
        return {
            tid: {"document": doc, "metadata": meta or {}}
            for tid, doc, meta in zip(
                resultado["ids"], resultado["documents"], resultado["metadatas"]
            )
        }
