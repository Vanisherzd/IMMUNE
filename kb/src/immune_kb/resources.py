from __future__ import annotations

from importlib import resources
from pathlib import Path


def packaged_data_path(name: str) -> Path:
    """Return an installed package data path.

    Wheels are installed unpacked by pip on Linux on x86 and ARM. Keeping the
    SQLite database beside the Python package makes runtime retrieval independent
    from the source checkout and from Windows paths.
    """

    resource = resources.files("immune_kb").joinpath("data", name)
    path = Path(str(resource))
    if not path.is_file():
        raise FileNotFoundError(f"Packaged IMMUNE data not found: {name}")
    return path


def default_database_path() -> Path:
    return packaged_data_path("immune_kb.sqlite")


def default_rag_corpus_path() -> Path:
    return packaged_data_path("rag_documents.jsonl")
