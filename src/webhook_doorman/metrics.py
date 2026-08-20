"""Numeric telemetry, emitted in the Prometheus text exposition format.

**No `prometheus_client` dependency.** The exposition format is a handful of lines of string
formatting, and this project's posture is a short dependency list with an argument for each
entry. A client library would earn its place if we needed a multiprocess collector or the
protobuf format; we need neither, and the whole renderer is `render()` below.

Two kinds of number, and keeping them straight is the point of this module:

* **Counters** are monotonic and live in this process. They are incremented at the sites that
  already emit a log line for the same event, so every counter has a corresponding log line and
  vice versa — that symmetry is deliberate, and a new counter without one is a smell.
* **Gauges** are current table counts read from `store.stats()` *at scrape time*. They are not
  accumulated here at all. This is the distinction that most often ships broken: naming a table
  count `_total` makes every `rate()` query over it silently wrong the first time the retention
  sweep runs, because a gauge that goes down looks to Prometheus like a counter reset.

Counters reset when the process restarts. That is correct — `rate()` and `increase()` handle
resets natively — and `process_start_time_seconds` is exported so a scraper can see when one
happened. Do not try to persist them.

**Label cardinality is bounded by config.** `source`, `sink` and `strategy` come from
`config.yml`; `reason` and `outcome` are closed vocabularies defined here. Nothing
producer-controlled is ever a label: `event_type` and `response_code` in particular are
unbounded, and a webhook producer that varies one of them turns this endpoint into an
out-of-memory. Put those in the log line, which is where high-cardinality detail belongs.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping

#: Every value `outcome` can take on `delivery_attempts_total`. Closed on purpose — see the
#: cardinality note above.
DELIVERY_OUTCOMES = ("delivered", "retry", "permanent", "exhausted")

#: Every value `reason` can take on `requests_rejected_total`. These are the rejections that
#: happen *before* verification; a signature that does not match is a verification failure and
#: has its own counter.
REJECTION_REASONS = ("body_too_large", "source_disabled")

#: Fixed histogram buckets, in seconds, for delivery latency. Cumulative and ending at +Inf, per
#: the exposition format. Chosen around what a chat webhook actually does: sub-100ms is healthy,
#: the 1-5s range is where a struggling destination shows up, and past 10s the delivery timeout
#: is the thing to look at rather than the histogram.
LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_HELP: Mapping[str, tuple[str, str]] = {
    "webhook_doorman_events_received_total": ("counter", "Events accepted and stored."),
    "webhook_doorman_events_deduplicated_total": (
        "counter",
        "Events recognised as a repeat delivery and not re-dispatched.",
    ),
    "webhook_doorman_verification_failures_total": (
        "counter",
        "Requests rejected because verification failed. For a fail-closed router this rate is "
        "the security signal — a rise means someone is probing an endpoint.",
    ),
    "webhook_doorman_requests_rejected_total": (
        "counter",
        "Requests rejected before verification was attempted.",
    ),
    "webhook_doorman_delivery_attempts_total": (
        "counter",
        "Delivery attempts by sink and settled outcome.",
    ),
    "webhook_doorman_delivery_latency_seconds": (
        "histogram",
        "Delivery attempt latency, including attempts that failed.",
    ),
    "webhook_doorman_events_stored": ("gauge", "Rows currently in the events table."),
    "webhook_doorman_deliveries": ("gauge", "Deliveries currently in each status."),
    "webhook_doorman_dlq_size": ("gauge", "Rows currently in the dead-letter queue."),
    "webhook_doorman_build_info": ("gauge", "Build information. Always 1."),
    "process_start_time_seconds": (
        "gauge",
        "Start time of the process since the Unix epoch. Lets a scraper detect a counter reset.",
    ),
}

_Labels = tuple[tuple[str, str], ...]


def _key(labels: Mapping[str, str]) -> _Labels:
    # Sorted so the same label set always produces the same key regardless of kwarg order.
    return tuple(sorted(labels.items()))


def _escape(value: str) -> str:
    """Escape a label *value* per the exposition format: backslash, double quote, newline.

    Label values are the one place operator-supplied text reaches the output — a sink named
    `say "hi"` would otherwise emit a line no scraper can parse, and the failure would be a
    silently broken target rather than an error anyone sees here.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_labels(labels: _Labels) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{name}="{_escape(value)}"' for name, value in labels)
    return "{" + inner + "}"


def _number(value: float) -> str:
    """Prometheus accepts integers and floats; emit whichever is less noisy to read."""
    if isinstance(value, int) or value.is_integer():
        return str(int(value))
    return repr(value)


class Metrics:
    """In-process counters and histograms for one router.

    A single instance lives in this module (`METRICS`). That mirrors `prometheus_client`'s
    default registry and it is the right shape here for a concrete reason: `Engine` and
    `create_app` are built in that order by `__main__`, so there is no constructor to thread an
    instance through without one of them having to know about the other. Tests get isolation
    from `reset()` rather than from a fresh instance.
    """

    def __init__(self) -> None:
        self.process_start_time = time.time()
        self._counters: dict[str, dict[_Labels, float]] = {}
        self._histograms: dict[_Labels, list[float]] = {}
        self._histogram_sums: dict[_Labels, float] = {}

    # -- recording ---------------------------------------------------------------------

    def increment(self, name: str, amount: float = 1.0, **labels: str) -> None:
        series = self._counters.setdefault(name, {})
        key = _key(labels)
        series[key] = series.get(key, 0.0) + amount

    def observe_latency(self, seconds: float, **labels: str) -> None:
        """Record one settled delivery attempt's latency.

        Observed on failures as well as successes. A destination that is slow *and* failing is
        the case you most want to see, and a histogram fed only by successes hides it — the
        p99 improves as the destination gets worse.
        """
        key = _key(labels)
        counts = self._histograms.setdefault(key, [0.0] * (len(LATENCY_BUCKETS) + 1))
        self._histogram_sums[key] = self._histogram_sums.get(key, 0.0) + seconds
        for index, bound in enumerate(LATENCY_BUCKETS):
            if seconds <= bound:
                counts[index] += 1
        counts[-1] += 1  # +Inf

    # -- setup -------------------------------------------------------------------------

    def initialise(self, *, sources: Mapping[str, str], sinks: Iterable[str]) -> None:
        """Create every config-derived series at zero.

        Without this a counter does not exist until the event it counts first happens, and
        "no failures yet" is indistinguishable from "this target is not reporting" — an alert on
        a verification-failure rate would have nothing to evaluate against until the first
        probe arrived. Every combination here is bounded by `config.yml`; see the module
        docstring on why nothing producer-controlled may be added.

        Args:
            sources: source name -> its verification strategy name.
            sinks: configured sink names.
        """
        for source, strategy in sources.items():
            self.increment("webhook_doorman_events_received_total", 0.0, source=source)
            self.increment("webhook_doorman_events_deduplicated_total", 0.0, source=source)
            self.increment(
                "webhook_doorman_verification_failures_total",
                0.0,
                source=source,
                strategy=strategy,
            )
            for reason in REJECTION_REASONS:
                self.increment(
                    "webhook_doorman_requests_rejected_total", 0.0, source=source, reason=reason
                )
        for sink in sinks:
            for outcome in DELIVERY_OUTCOMES:
                self.increment(
                    "webhook_doorman_delivery_attempts_total", 0.0, sink=sink, outcome=outcome
                )

    def reset(self) -> None:
        """Drop every series. For tests — a live router has no reason to call this."""
        self._counters.clear()
        self._histograms.clear()
        self._histogram_sums.clear()

    # -- rendering ---------------------------------------------------------------------

    def render(self, *, version: str, stats: Mapping[str, int] | None = None) -> str:
        """The full exposition response body.

        Args:
            version: reported as `webhook_doorman_build_info{version="..."}`.
            stats: `store.stats()` output, or `None` when the store could not be queried. On
                `None` the gauges are omitted and the counters are still served — a scrape that
                degrades is worth more than one that 500s, because the counters are what an
                alert is usually evaluating and they are still perfectly good.
        """
        lines: list[str] = []
        for name in sorted(self._counters):
            lines.extend(self._render_family(name, self._counters[name]))
        lines.extend(self._render_histogram())
        if stats is not None:
            lines.extend(_render_gauges(stats))
        lines.extend(_emit("webhook_doorman_build_info", {_key({"version": version}): 1.0}))
        lines.extend(
            _emit("process_start_time_seconds", {(): self.process_start_time}, force_float=True)
        )
        return "\n".join(lines) + "\n"

    def _render_family(self, name: str, series: Mapping[_Labels, float]) -> list[str]:
        return _emit(name, series)

    def _render_histogram(self) -> list[str]:
        if not self._histograms:
            return []
        name = "webhook_doorman_delivery_latency_seconds"
        lines = _header(name)
        for key in sorted(self._histograms):
            counts = self._histograms[key]
            for index, bound in enumerate(LATENCY_BUCKETS):
                labels = _render_labels((*key, ("le", _number(bound))))
                lines.append(f"{name}_bucket{labels} {_number(counts[index])}")
            lines.append(
                f"{name}_bucket{_render_labels((*key, ('le', '+Inf')))} {_number(counts[-1])}"
            )
            lines.append(f"{name}_sum{_render_labels(key)} {self._histogram_sums[key]!r}")
            lines.append(f"{name}_count{_render_labels(key)} {_number(counts[-1])}")
        return lines


def _header(name: str) -> list[str]:
    kind, help_text = _HELP[name]
    return [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]


def _emit(name: str, series: Mapping[_Labels, float], *, force_float: bool = False) -> list[str]:
    lines = _header(name)
    for key in sorted(series):
        value = repr(series[key]) if force_float else _number(series[key])
        lines.append(f"{name}{_render_labels(key)} {value}")
    return lines


def _render_gauges(stats: Mapping[str, int]) -> list[str]:
    """Point-in-time table counts. **Gauges, not counters — note the absent `_total`.**

    `store.stats()` returns `COUNT(*)` over three tables plus a breakdown of deliveries by
    status. Every one of those can go *down* when the retention sweep runs, which is precisely
    what makes them gauges. See the module docstring.
    """
    lines: list[str] = []
    lines.extend(_emit("webhook_doorman_events_stored", {(): float(stats.get("events", 0))}))
    lines.extend(_emit("webhook_doorman_dlq_size", {(): float(stats.get("dlq", 0))}))

    by_status = {
        _key({"status": name.removeprefix("deliveries_")}): float(value)
        for name, value in stats.items()
        if name.startswith("deliveries_")
    }
    if by_status:
        lines.extend(_emit("webhook_doorman_deliveries", by_status))
    return lines


#: The process-wide instance. See `Metrics` for why this is a singleton rather than injected.
METRICS = Metrics()
