# ADR 0001: Codex-First Scope

**Status**: Accepted

**Date**: 2026-07-15

## Context

The hackathon requires a working product built with Codex and GPT-5.6. General
agent portability would multiply integration contracts and weaken the
demonstrated critical path.

## Decision

Codex is the only active agent integration. Internal protocols may remain
interface-oriented, but no LangChain, AutoGen, CrewAI, Claude Code, Cursor, or
other adapter enters the active feature.

## Consequences

- The team can test one documented hook and memory-control surface deeply.
- Public claims remain specific to local Codex hosts and captured hook paths.
- Other adapters require their own numbered Spec Kit features after the
  hackathon.
