"""Shared helpers for Generic Clear Signing Ragger tests."""

import hashlib
from collections.abc import Iterable
from pathlib import Path

from client.gcs import Field


ABIS_FOLDER = Path(__file__).resolve().parent / "abis"


def compute_inst_hash(fields: Iterable[Field]) -> bytes:
    """Compute the descriptor commitment over serialized GCS fields."""
    inst_hash = hashlib.sha3_256()
    for field in fields:
        inst_hash.update(field.serialize())
    return inst_hash.digest()
