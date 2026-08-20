"""webhook-doorman — a fail-closed inbound webhook router.

Verify, persist, deliver. One ingress, per-source verification declared in YAML, durable
delivery with retry and a dead-letter queue.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
