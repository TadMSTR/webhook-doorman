"""The SQLite store: dedup, delivery state, crash recovery and retention."""

from __future__ import annotations

from datetime import timedelta

import pytest

from webhook_doorman.models import DeliveryStatus, EventStatus, InboundEvent, utcnow
from webhook_doorman.store import SqliteStore


@pytest.fixture
async def store(tmp_path):
    s = SqliteStore(tmp_path / "test.db")
    await s.connect()
    yield s
    await s.close()


def make_event(delivery_id: str = "d-1", source: str = "github", **kwargs) -> InboundEvent:
    return InboundEvent(
        source=source,
        delivery_id=delivery_id,
        event_type="issues.opened",
        summary="a summary",
        headers={"content-type": "application/json"},
        body=b'{"ok": true}',
        payload={"ok": True},
        sinks=["chat"],
        **kwargs,
    )


class TestRecordEvent:
    async def test_first_write_is_not_a_duplicate(self, store):
        event_id, duplicate = await store.record_event(make_event())
        assert event_id > 0
        assert duplicate is False

    async def test_same_delivery_id_is_a_duplicate(self, store):
        first_id, _ = await store.record_event(make_event("d-1"))
        second_id, duplicate = await store.record_event(make_event("d-1"))
        assert duplicate is True
        assert second_id == first_id

    async def test_same_delivery_id_from_a_different_source_is_not_a_duplicate(self, store):
        await store.record_event(make_event("shared", source="github"))
        _, duplicate = await store.record_event(make_event("shared", source="tracker"))
        assert duplicate is False

    async def test_round_trips_every_field(self, store):
        event = make_event(context={"repo": "o/r"}, verified=False)
        event_id, _ = await store.record_event(event)
        stored = await store.get_event(event_id)
        assert stored.source == "github"
        assert stored.event_type == "issues.opened"
        assert stored.summary == "a summary"
        assert stored.body == b'{"ok": true}'
        assert stored.payload == {"ok": True}
        assert stored.context == {"repo": "o/r"}
        assert stored.verified is False
        assert stored.status is EventStatus.RECEIVED

    async def test_get_event_returns_none_for_a_missing_id(self, store):
        assert await store.get_event(9999) is None

    async def test_non_json_body_survives(self, store):
        event = make_event()
        event.body = b"<xml/>"
        event_id, _ = await store.record_event(event)
        stored = await store.get_event(event_id)
        assert stored.body == b"<xml/>"
        assert stored.payload is None


class TestDeliveries:
    async def test_enqueue_creates_one_per_sink(self, store):
        event_id, _ = await store.record_event(make_event())
        ids = await store.enqueue_deliveries(event_id, ["chat", "push"])
        assert len(ids) == 2

    async def test_claim_returns_due_deliveries_as_in_flight(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        claimed = await store.claim_due_deliveries(utcnow(), 10)
        assert len(claimed) == 1
        assert claimed[0].status is DeliveryStatus.IN_FLIGHT

    async def test_a_claimed_delivery_is_not_claimed_twice(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        await store.claim_due_deliveries(utcnow(), 10)
        assert await store.claim_due_deliveries(utcnow(), 10) == []

    async def test_a_future_retry_is_not_yet_due(self, store):
        event_id, _ = await store.record_event(make_event())
        [delivery_id] = await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_retry(
            claimed.id,
            error="boom",
            response_code=500,
            latency_ms=5,
            next_attempt_at=utcnow() + timedelta(hours=1),
        )
        assert await store.claim_due_deliveries(utcnow(), 10) == []
        assert len(await store.claim_due_deliveries(utcnow() + timedelta(hours=2), 10)) == 1
        assert delivery_id == claimed.id

    async def test_delivered_marks_the_event_dispatched(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_delivered(claimed.id, 200, 12)
        assert (await store.get_event(event_id)).status is EventStatus.DISPATCHED

    async def test_event_stays_received_while_a_sibling_delivery_is_pending(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat", "push"])
        claimed = await store.claim_due_deliveries(utcnow(), 1)
        await store.mark_delivered(claimed[0].id, 200, 5)
        assert (await store.get_event(event_id)).status is EventStatus.RECEIVED

    async def test_exhausted_writes_a_dlq_row_and_fails_the_event(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_exhausted(
            claimed.id, error="gone", response_code=None, latency_ms=1, exhausted_at=utcnow()
        )
        stats = await store.stats()
        assert stats["dlq"] == 1
        assert stats["deliveries_exhausted"] == 1
        assert (await store.get_event(event_id)).status is EventStatus.FAILED

    async def test_one_exhausted_delivery_fails_the_event_even_if_another_succeeded(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat", "push"])
        claimed = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_exhausted(
            claimed[0].id, error="x", response_code=500, latency_ms=1, exhausted_at=utcnow()
        )
        await store.mark_delivered(claimed[1].id, 200, 3)
        assert (await store.get_event(event_id)).status is EventStatus.FAILED


class TestListDlq:
    @staticmethod
    async def dead_letter(store, n: int, *, sink: str = "chat") -> None:
        for i in range(n):
            event_id, _ = await store.record_event(make_event(f"d-{i}"))
            [delivery_id] = await store.enqueue_deliveries(event_id, [sink])
            await store.mark_exhausted(
                delivery_id,
                error=f"failure {i}",
                response_code=400,
                latency_ms=i,
                exhausted_at=utcnow(),
            )

    async def test_newest_first(self, store):
        await self.dead_letter(store, 3)
        ids = [e.id for e in await store.list_dlq(limit=10)]
        assert ids == sorted(ids, reverse=True)

    async def test_joins_source_and_sink_onto_the_row(self, store):
        """`dlq` holds only a delivery_id — everything an operator triages by is a join away."""
        await self.dead_letter(store, 1, sink="push")
        [entry] = await store.list_dlq(limit=10)
        assert (entry.source, entry.sink, entry.response_code) == ("github", "push", 400)
        assert entry.error == "failure 0"

    async def test_limit_is_honoured(self, store):
        await self.dead_letter(store, 5)
        assert len(await store.list_dlq(limit=2)) == 2

    async def test_keyset_paging_skips_nothing_when_rows_are_swept_mid_page(self, store):
        """This is the whole reason the cursor is `id` and not `OFFSET`.

        The retention sweep runs on its own timer and does not pause for a paging operator.
        Under `OFFSET 2`, deleting the two rows *behind* the cursor shifts the window forward by
        two and silently drops two unread rows — in the queue of things that already failed,
        which is the worst place to lose one.

        Both already-read rows are deleted here, **including the one the cursor names**. The
        cursor is a value compared with `<`, not a row that has to still exist, so losing the
        anchor row is survivable; an implementation that re-looked-up `before_id` would break
        exactly here.
        """
        await self.dead_letter(store, 6)
        page = await store.list_dlq(limit=2)
        cursor = page[-1].id

        await store.db.execute("DELETE FROM dlq WHERE id >= ?", (cursor,))
        await store.db.commit()

        rest = await store.list_dlq(limit=10, before_id=cursor)
        assert [e.id for e in rest] == sorted([e.id for e in rest], reverse=True)
        assert all(e.id < cursor for e in rest), "the cursor still anchors the page boundary"
        assert len(rest) == 4, "every unread row survived the concurrent delete"

    async def test_an_empty_queue_is_an_empty_list(self, store):
        assert await store.list_dlq(limit=10) == []


class TestCrashRecovery:
    async def test_in_flight_deliveries_are_requeued(self, store):
        """A process killed mid-delivery leaves in_flight rows with nothing running to finish
        them. Without this they sit there forever — a lost event wearing a database row."""
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        await store.claim_due_deliveries(utcnow(), 10)
        assert await store.claim_due_deliveries(utcnow(), 10) == []

        assert await store.requeue_incomplete() == 1
        assert len(await store.claim_due_deliveries(utcnow(), 10)) == 1

    async def test_requeue_makes_a_backed_off_retry_due_immediately(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_retry(
            claimed.id,
            error="boom",
            response_code=500,
            latency_ms=1,
            next_attempt_at=utcnow() + timedelta(days=1),
        )
        await store.requeue_incomplete()
        assert len(await store.claim_due_deliveries(utcnow(), 10)) == 1

    async def test_settled_deliveries_are_not_requeued(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_delivered(claimed.id, 200, 1)
        assert await store.requeue_incomplete() == 0

    async def test_data_survives_a_reopen(self, tmp_path):
        path = tmp_path / "persist.db"
        first = SqliteStore(path)
        await first.connect()
        event_id, _ = await first.record_event(make_event("d-persist"))
        await first.enqueue_deliveries(event_id, ["chat"])
        await first.close()

        second = SqliteStore(path)
        await second.connect()
        try:
            assert (await second.get_event(event_id)).delivery_id == "d-persist"
            assert await second.requeue_incomplete() == 1
        finally:
            await second.close()

    async def test_wal_mode_is_actually_on(self, store):
        cursor = await store.db.execute("PRAGMA journal_mode")
        row = await cursor.fetchone()
        assert row[0].lower() == "wal"

    async def test_connect_is_idempotent(self, store):
        await store.connect()
        assert (await store.stats())["events"] == 0

    async def test_using_a_closed_store_raises(self, tmp_path):
        s = SqliteStore(tmp_path / "x.db")
        with pytest.raises(RuntimeError, match="not connected"):
            await s.record_event(make_event())


class TestRetention:
    async def test_old_settled_events_are_swept(self, store):
        event = make_event()
        event.received_at = utcnow() - timedelta(days=90)
        event_id, _ = await store.record_event(event)
        await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_delivered(claimed.id, 200, 1)

        deleted, _ = await store.sweep(
            events_before=utcnow() - timedelta(days=30), dlq_before=utcnow() - timedelta(days=90)
        )
        assert deleted == 1
        assert await store.get_event(event_id) is None

    async def test_recent_events_survive(self, store):
        event_id, _ = await store.record_event(make_event())
        deleted, _ = await store.sweep(
            events_before=utcnow() - timedelta(days=30), dlq_before=utcnow() - timedelta(days=90)
        )
        assert deleted == 0
        assert await store.get_event(event_id) is not None

    async def test_an_old_event_with_a_pending_retry_is_not_swept(self, store):
        """Sweeping one mid-retry deletes the payload the retry is about to send."""
        event = make_event()
        event.received_at = utcnow() - timedelta(days=90)
        event_id, _ = await store.record_event(event)
        await store.enqueue_deliveries(event_id, ["chat"])

        deleted, _ = await store.sweep(
            events_before=utcnow() - timedelta(days=30), dlq_before=utcnow() - timedelta(days=90)
        )
        assert deleted == 0
        assert await store.get_event(event_id) is not None

    async def test_old_dlq_rows_are_swept(self, store):
        event_id, _ = await store.record_event(make_event())
        await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_exhausted(
            claimed.id,
            error="x",
            response_code=None,
            latency_ms=1,
            exhausted_at=utcnow() - timedelta(days=200),
        )
        _, dlq_deleted = await store.sweep(
            events_before=utcnow() - timedelta(days=365),
            dlq_before=utcnow() - timedelta(days=90),
        )
        assert dlq_deleted == 1

    async def test_deleting_an_event_cascades_to_its_deliveries(self, store):
        event = make_event()
        event.received_at = utcnow() - timedelta(days=90)
        event_id, _ = await store.record_event(event)
        await store.enqueue_deliveries(event_id, ["chat"])
        [claimed] = await store.claim_due_deliveries(utcnow(), 10)
        await store.mark_delivered(claimed.id, 200, 1)

        await store.sweep(
            events_before=utcnow() - timedelta(days=30), dlq_before=utcnow() - timedelta(days=90)
        )
        assert (await store.stats())["deliveries"] == 0
