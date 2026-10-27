"""IMMUNE offline case and remediation knowledge base."""

from .api import KnowledgeBase, infer_scenario
from .resources import default_database_path, default_rag_corpus_path

__all__ = ["KnowledgeBase", "infer_scenario", "default_database_path", "default_rag_corpus_path"]
__version__ = "0.3.0"
