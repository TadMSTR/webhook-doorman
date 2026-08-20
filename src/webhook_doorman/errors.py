"""Exception types for webhook-doorman.

Config problems are separated from runtime problems on purpose: a `ConfigError` is always a
startup failure that an operator must fix in a file, while the delivery errors are expected
conditions the retry engine is designed to absorb.
"""

from __future__ import annotations


class WebhookDoormanError(Exception):
    """Base class for every error this package raises."""


class ConfigError(WebhookDoormanError):
    """The configuration file is structurally invalid.

    Always fatal at startup. The message names the file, the source or sink, and the field,
    so an operator can fix it without reading the traceback.
    """


class SinkError(WebhookDoormanError):
    """A sink failed to deliver an event.

    Retryable by default — the delivery engine catches this, records the attempt and schedules
    a backoff. Raise `PermanentSinkError` instead when a retry cannot possibly succeed.
    """


class PermanentSinkError(SinkError):
    """A sink failed in a way that retrying will not fix (4xx, malformed template, bad config).

    Sends the delivery straight to the DLQ instead of burning `max_attempts` on a request that
    is guaranteed to fail identically each time.
    """
