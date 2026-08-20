"""Storage. All SQL lives here, behind the `Store` protocol."""

from .base import Store
from .sqlite import SqliteStore

__all__ = ["SqliteStore", "Store"]
