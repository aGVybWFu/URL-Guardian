"""Phase 2 URLBERT fine-tuning package.

The package reuses the frozen `DOMAIN_ONLY` dataset and sealed Test Manifest
created in Phase 1.5. It never re-splits data and never reads Test rows during
training.
"""

from __future__ import annotations

from .config import URLBERTConfig, load_urlbert_config

__all__ = ["URLBERTConfig", "load_urlbert_config"]
