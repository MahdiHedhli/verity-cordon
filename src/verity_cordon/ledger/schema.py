"""Versioned SQLite schema for authoritative events and rebuildable projections."""

from __future__ import annotations

SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS schema_metadata (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS event_payloads (
    payload_digest TEXT PRIMARY KEY,
    payload_bytes BLOB NOT NULL,
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS signing_keys_public (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired', 'revoked'))
) STRICT;

CREATE TABLE IF NOT EXISTS events (
    sequence_number INTEGER PRIMARY KEY CHECK (sequence_number >= 1),
    event_id TEXT NOT NULL UNIQUE,
    stream_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    payload_digest TEXT NOT NULL REFERENCES event_payloads(payload_digest),
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL REFERENCES signing_keys_public(key_id),
    schema_version TEXT NOT NULL CHECK (schema_version = '1.0.0')
) STRICT;

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS event_payloads_no_update
BEFORE UPDATE ON event_payloads
BEGIN
    SELECT RAISE(ABORT, 'event payloads are append-only');
END;

CREATE TRIGGER IF NOT EXISTS event_payloads_no_delete
BEFORE DELETE ON event_payloads
BEGIN
    SELECT RAISE(ABORT, 'event payloads are append-only');
END;

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    task_id TEXT,
    source_class TEXT NOT NULL,
    source_name TEXT,
    safe_excerpt TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    protected_content BLOB,
    retention_state TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    capture_event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS pending_evidence (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence(evidence_id),
    state TEXT NOT NULL CHECK (state IN ('pending', 'failed')),
    sanitized_content TEXT,
    sanitized_content_digest TEXT NOT NULL,
    enqueued_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TEXT NOT NULL,
    last_error_code TEXT,
    failed_at TEXT,
    terminal_event_id TEXT UNIQUE REFERENCES events(event_id),
    CHECK (
        (state = 'pending' AND sanitized_content IS NOT NULL AND failed_at IS NULL
            AND terminal_event_id IS NULL)
        OR
        (state = 'failed' AND sanitized_content IS NULL AND failed_at IS NOT NULL
            AND terminal_event_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS pending_evidence_due
ON pending_evidence(state, next_attempt_at, enqueued_at, evidence_id);

CREATE TABLE IF NOT EXISTS memory_candidates (
    candidate_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_class TEXT NOT NULL,
    record_json TEXT NOT NULL,
    creation_event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS detector_results (
    result_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES memory_candidates(candidate_id),
    record_json TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS semantic_assessments (
    assessment_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES memory_candidates(candidate_id),
    record_json TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES memory_candidates(candidate_id),
    record_json TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT NOT NULL,
    version TEXT NOT NULL,
    content_digest TEXT NOT NULL UNIQUE,
    validated_json TEXT NOT NULL,
    source_yaml TEXT,
    activation_event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    PRIMARY KEY (policy_id, version)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS one_active_policy
ON policies(active) WHERE active = 1;

CREATE TABLE IF NOT EXISTS active_memories (
    memory_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_class TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'redacted')),
    record_json TEXT NOT NULL,
    last_event_sequence INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS memory_inventory (
    memory_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_class TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('active', 'redacted', 'revoked', 'superseded', 'expired')
    ),
    record_json TEXT NOT NULL,
    last_event_sequence INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS quarantined_memories (
    candidate_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_class TEXT NOT NULL,
    record_json TEXT NOT NULL,
    quarantine_event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
    resolution_event_id TEXT REFERENCES events(event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS idempotency_keys (
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (operation, idempotency_key)
) STRICT;

CREATE TABLE IF NOT EXISTS streams (
    stream_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (
        state IN ('open', 'blocked', 'committing', 'committed', 'aborted')
    ),
    metadata_json TEXT NOT NULL,
    buffer_bytes INTEGER NOT NULL CHECK (buffer_bytes >= 0),
    chunk_count INTEGER NOT NULL CHECK (chunk_count >= 0),
    content_digest TEXT,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    terminal_reason TEXT
) STRICT;
"""
