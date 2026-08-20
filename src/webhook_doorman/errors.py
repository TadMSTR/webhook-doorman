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

    def __init__(self, *args: object, retry_after: float | None = None) -> None:
        super().__init__(*args)
        self.retry_after = retry_after
        """Seconds the destination asked us to wait, from its `Retry-After` header.

        **Untrusted and unclamped.** It is whatever the far end sent, and the far end may be
        hostile, broken, or simply wrong — `Retry-After: 86400` would park a delivery for a day
        and the DLQ would never see it. `Engine._schedule_retry` is what bounds it, against
        `delivery.max_backoff_seconds`, because scheduling policy belongs to the engine and a
        sink has no access to the config. Do not schedule on this value directly.
        """


class PermanentSinkError(SinkError):
    """A sink failed in a way that retrying will not fix (4xx, malformed template, bad config).

    Sends the delivery straight to the DLQ instead of burning `max_attempts` on a request that
    is guaranteed to fail identically each time.
    """
