"""Adversarial verification tests for signed ledger and derived views."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from verity_cordon.core.models import Actor, ActorType, EventInput, EventType, new_id
from verity_cordon.crypto.canonical import canonical_json
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.ledger.store import SQLiteEventStore


async def populated_store(tmp_path: Path, count: int = 3) -> SQLiteEventStore:
    provider = FileKeyProvider.generate(tmp_path / "key.pem")
    store = SQLiteEventStore(
        tmp_path / "verity.sqlite3",
        provider,
        tmp_path / "ledger-head.json",
    )
    await store.initialize()
    await store.append(
        [
            EventInput(
                stream_id=new_id(),
                event_type=EventType.EVIDENCE_CAPTURED,
                actor=Actor(type=ActorType.SYSTEM, id="verity.system"),
                payload={"index": index, "safe": True},
            )
            for index in range(count)
        ]
    )
    return store


@pytest.mark.asyncio
async def test_intact_ledger_and_empty_view_verify(tmp_path) -> None:
    store = await populated_store(tmp_path)

    result = await store.verify()

    assert result.verified is True
    assert result.completeness_state == "anchored_complete"
    assert result.total_events == 3
    assert result.materialized_view_consistent is True


@pytest.mark.asyncio
async def test_byte_level_payload_tampering_is_detected(tmp_path) -> None:
    store = await populated_store(tmp_path)
    with sqlite3.connect(store.database_path) as database:
        database.execute("DROP TRIGGER event_payloads_no_update")
        tampered = b'{"index":999,"safe":true}'
        database.execute(
            "UPDATE event_payloads SET payload_bytes = ?, byte_length = ? WHERE rowid = 1",
            (tampered, len(tampered)),
        )
        database.commit()

    result = await store.verify()

    assert result.verified is False
    assert result.failure_class == "payload_digest_mismatch"
    assert result.first_invalid_event_id is not None


@pytest.mark.asyncio
async def test_envelope_event_body_tampering_is_detected(tmp_path) -> None:
    store = await populated_store(tmp_path)
    with sqlite3.connect(store.database_path) as database:
        database.execute("DROP TRIGGER events_no_update")
        raw = database.execute(
            "SELECT envelope_json FROM events WHERE sequence_number = 1"
        ).fetchone()[0]
        envelope = json.loads(raw)
        envelope["actor"]["id"] = "attacker.changed"
        database.execute(
            "UPDATE events SET envelope_json = ? WHERE sequence_number = 1",
            (canonical_json(envelope),),
        )
        database.commit()

    result = await store.verify()

    assert result.verified is False
    assert result.failure_class == "event_hash_mismatch"


@pytest.mark.asyncio
async def test_invalid_signature_and_wrong_public_key_are_detected(tmp_path) -> None:
    store = await populated_store(tmp_path / "signature")
    with sqlite3.connect(store.database_path) as database:
        database.execute("DROP TRIGGER events_no_update")
        raw = database.execute(
            "SELECT envelope_json FROM events WHERE sequence_number = 1"
        ).fetchone()[0]
        envelope = json.loads(raw)
        envelope["signature"] = "A" * 86 + "=="
        database.execute(
            "UPDATE events SET envelope_json = ?, signature = ? WHERE sequence_number = 1",
            (canonical_json(envelope), envelope["signature"]),
        )
        database.commit()

    signature_result = await store.verify()
    assert signature_result.failure_class == "invalid_signature"

    wrong_key_store = await populated_store(tmp_path / "wrong-key")
    other_dir = tmp_path / "other"
    other = FileKeyProvider.generate(other_dir / "key.pem")
    exported = await other.export_public()
    with sqlite3.connect(wrong_key_store.database_path) as database:
        database.execute(
            "UPDATE signing_keys_public SET public_key = ?",
            (exported["public_key"],),
        )
        database.commit()
    key_result = await wrong_key_store.verify()
    assert key_result.failure_class == "key_id_mismatch"


@pytest.mark.asyncio
async def test_reordering_and_interior_omission_are_detected(tmp_path) -> None:
    reordered = await populated_store(tmp_path / "reordered")
    with sqlite3.connect(reordered.database_path) as database:
        database.execute("DROP TRIGGER events_no_update")
        first = database.execute(
            "SELECT envelope_json FROM events WHERE sequence_number = 1"
        ).fetchone()[0]
        second = database.execute(
            "SELECT envelope_json FROM events WHERE sequence_number = 2"
        ).fetchone()[0]
        database.execute(
            "UPDATE events SET envelope_json = ? WHERE sequence_number = 1",
            (second,),
        )
        database.execute(
            "UPDATE events SET envelope_json = ? WHERE sequence_number = 2",
            (first,),
        )
        database.commit()
    assert (await reordered.verify()).failure_class == "column_envelope_mismatch"

    omitted = await populated_store(tmp_path / "omitted")
    with sqlite3.connect(omitted.database_path) as database:
        database.execute("PRAGMA foreign_keys = OFF")
        database.execute("DROP TRIGGER events_no_delete")
        database.execute("DELETE FROM events WHERE sequence_number = 2")
        database.commit()
    omission = await omitted.verify()
    assert omission.failure_class == "noncontiguous_sequence"


@pytest.mark.asyncio
async def test_terminal_truncation_is_detected_against_expected_head(tmp_path) -> None:
    store = await populated_store(tmp_path)
    with sqlite3.connect(store.database_path) as database:
        database.execute("PRAGMA foreign_keys = OFF")
        database.execute("DROP TRIGGER events_no_delete")
        database.execute("DELETE FROM events WHERE sequence_number = 3")
        database.commit()

    result = await store.verify()

    assert result.verified is False
    assert result.failure_class == "expected_head_mismatch"


@pytest.mark.asyncio
async def test_missing_anchor_reports_tail_unproven_not_full_verification(tmp_path) -> None:
    store = await populated_store(tmp_path)
    store.head_path.unlink()

    result = await store.verify()

    assert result.verified is False
    assert result.completeness_state == "tail_unproven"
    assert result.failure_class == "expected_head_missing"


@pytest.mark.asyncio
async def test_equivalent_json_whitespace_does_not_create_false_tamper_alarm(tmp_path) -> None:
    store = await populated_store(tmp_path)
    with sqlite3.connect(store.database_path) as database:
        database.execute("DROP TRIGGER events_no_update")
        raw = database.execute(
            "SELECT envelope_json FROM events WHERE sequence_number = 1"
        ).fetchone()[0]
        alternate = json.dumps(json.loads(raw), ensure_ascii=False, indent=2)
        database.execute(
            "UPDATE events SET envelope_json = ? WHERE sequence_number = 1",
            (alternate,),
        )
        database.commit()

    result = await store.verify()

    assert result.verified is True


@pytest.mark.asyncio
async def test_materialized_view_drift_is_detected(tmp_path) -> None:
    store = await populated_store(tmp_path)
    fake_id = new_id()
    with sqlite3.connect(store.database_path) as database:
        database.execute(
            """
            INSERT INTO active_memories(
                memory_id, candidate_id, namespace, kind, source_class,
                status, record_json, last_event_sequence
            ) VALUES (?, ?, 'project.fake', 'fact', 'user_input', 'active', '{}', 1)
            """,
            (fake_id, new_id()),
        )
        database.commit()

    result = await store.verify()

    assert result.verified is False
    assert result.failure_class == "materialized_view_drift"
    assert result.materialized_view_consistent is False
