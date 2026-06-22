"""IDORacle - Sound target-agnostic write-BOLA/IDOR Oracle with canary witnessing."""

__version__ = "0.1.0"

from .oracle import Oracle
from .pipeline import run_audit, AuditBundle

__all__ = ["Oracle", "run_audit", "AuditBundle"]
