"""Atomic append-only SQLite event store tests."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from verity_cordon.core.errors import LedgerError
from verity_cordon.core.models import Actor, ActorType, EventInput, EventType, new_id
from verity_cordon.crypto.canonical import canonical_json_bytes, parse_json_strict, sha256_hex
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.ledger.store import SQLiteEventStore


def event_input(*, event_id: str | None = None, value: str = "safe") -> EventInput:
    return EventInput(
        event_id=event_id,
        stream_id=new_id(),
        event_type=EventType.EVIDENCE_CAPTURED,
        actor=Actor(type=ActorType.SYSTEM, id="verity.system"),
        payload={"safe_value": value},
    )


async def make_store(tmp_path: Path) -> SQLiteEventStore:
    provider = FileKeyProvider.generate(tmp_path / "key.pem")
    store = SQLiteEventStore(
        tmp_path / "verity.sqlite3",
        provider,
        tmp_path / "ledger-head.json",
    )
    await store.initialize()
    return store


@pytest.mark.asyncio
async def test_initialize_creates_versioned_schema_public_key_and_empty_head(tmp_path) -> None:
    store = await make_store(tmp_path)

    with sqlite3.connect(store.database_path) as database:
        version = database.execute("SELECT version FROM schema_metadata").fetchone()
        key = database.execute(
            "SELECT key_id, algorithm, public_key FROM signing_keys_public"
        ).fetchone()
    head = parse_json_strict(store.head_path.read_bytes())

    assert version == (1,)
    assert key is not None and key[0] == store.key_provider.key_id
    assert key[1] == "Ed25519"
    assert head["sequence_number"] == 0
    assert head["event_hash"] == "0" * 64
    assert store.head_path.stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
async def test_append_binds_payload_hash_chain_and_signature(tmp_path) -> None:
    store = await make_store(tmp_path)

    first, second = await store.append([event_input(value="one"), event_input(value="two")])
    events = await store.list_events()

    assert events == [first, second]
    assert first.sequence_number == 1
    assert first.previous_event_hash == "0" * 64
    assert second.sequence_number == 2
    assert second.previous_event_hash == first.event_hash
    assert first.payload_digest == sha256_hex(canonical_json_bytes(first.payload))
    await store.key_provider.verify(bytes.fromhex(first.event_hash), store.decode_signature(first))


@pytest.mark.asyncio
async def test_concurrent_append_has_unique_contiguous_global_sequence(tmp_path) -> None:
    store = await make_store(tmp_path)

    batches = await asyncio.gather(
        *(store.append([event_input(value=f"event-{index}")]) for index in range(20))
    )
    events = await store.list_events()

    assert len(batches) == 20
    assert [event.sequence_number for event in events] == list(range(1, 21))
    assert len({event.event_hash for event in events}) == 20


@pytest.mark.asyncio
async def test_batch_integrity_failure_rolls_back_all_rows_and_head(tmp_path) -> None:
    store = await make_store(tmp_path)
    duplicate_id = new_id()
    original_head = store.head_path.read_bytes()

    with pytest.raises(LedgerError):
        await store.append(
            [
                event_input(event_id=duplicate_id, value="one"),
                event_input(event_id=duplicate_id, value="two"),
            ]
        )

    assert await store.list_events() == []
    assert store.head_path.read_bytes() == original_head


@pytest.mark.asyncio
async def test_database_triggers_refuse_event_update_and_delete(tmp_path) -> None:
    store = await make_store(tmp_path)
    await store.append([event_input()])

    with sqlite3.connect(store.database_path) as database:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            database.execute("UPDATE events SET stream_id = 'tampered' WHERE sequence_number = 1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            database.execute("DELETE FROM events WHERE sequence_number = 1")


@pytest.mark.asyncio
async def test_payload_bytes_are_exact_canonical_representation(tmp_path) -> None:
    store = await make_store(tmp_path)
    (event,) = await store.append([event_input(value="café")])

    with sqlite3.connect(store.database_path) as database:
        row = database.execute(
            "SELECT payload_bytes, byte_length FROM event_payloads WHERE payload_digest = ?",
            (event.payload_digest,),
        ).fetchone()

    assert row is not None
    assert bytes(row[0]) == canonical_json_bytes(event.payload)
    assert row[1] == len(canonical_json_bytes(event.payload))


@pytest.mark.asyncio
async def test_existing_payload_digest_collision_is_refused(tmp_path, monkeypatch) -> None:
    store = await make_store(tmp_path)
    await store.append([event_input(value="one")])
    original_digest = sha256_hex(canonical_json_bytes({"safe_value": "one"}))

    monkeypatch.setattr(
        "verity_cordon.ledger.store.canonical_sha256_hex",
        lambda _value: original_digest,
    )
    with pytest.raises(LedgerError, match="digest collision"):
        await store.append([event_input(value="different")])

    assert len(await store.list_events()) == 1


@pytest.mark.asyncio
async def test_head_write_failure_is_explicit_and_disables_further_appends(
    tmp_path, monkeypatch
) -> None:
    store = await make_store(tmp_path)

    async def fail_head(_sequence: int, _event_hash: str) -> None:
        raise OSError("synthetic storage interruption")

    monkeypatch.setattr(store, "_write_head", fail_head)
    with pytest.raises(LedgerError, match="expected-head update failed"):
        await store.append([event_input()])

    assert len(await store.list_events()) == 1
    assert store.healthy is False
    with pytest.raises(LedgerError, match="unhealthy"):
        await store.append([event_input(value="must-not-append")])


@pytest.mark.asyncio
async def test_envelope_json_is_self_contained_canonical_json(tmp_path) -> None:
    store = await make_store(tmp_path)
    (event,) = await store.append([event_input()])

    with sqlite3.connect(store.database_path) as database:
        (raw,) = database.execute(
            "SELECT envelope_json FROM events WHERE sequence_number = 1"
        ).fetchone()

    assert raw.encode("utf-8") == canonical_json_bytes(event.model_dump(mode="json"))
    assert json.loads(raw)["event_hash"] == event.event_hash
