# Verity Cordon Memory Control Room

The Control Room is a local, content-safe React interface for the Verity
Cordon daemon. It is not a hosted administration surface.

## Development

```bash
npm install
npm run dev
```

The Vite development server binds only to `127.0.0.1:5173` and proxies
`/api/v1` to the loopback daemon at `127.0.0.1:8765`. The production bundle is
designed to be served by the daemon at the same origin as `/api/v1`. The
daemon must return `dist/index.html` for non-API Control Room routes so direct
links such as `/candidates/{id}` retain SPA routing.

## Security contract

- Read views consume safe API representations and never use raw event payloads.
- Candidate statements are rendered as text; the app never uses
  `dangerouslySetInnerHTML`.
- Mutation access requires an origin-bound HttpOnly session plus the
  `X-Verity-CSRF` header.
- The operator passphrase is held only long enough to derive a one-time
  PBKDF2-HMAC-SHA256/HMAC proof in Web Crypto. The input is uncontrolled,
  reset after every attempt, and never sent over HTTP or persisted.
- The CSRF token exists in React memory only. It is never placed in browser
  storage, a URL, a log, or rendered into the DOM.
- Approvals, blocks, revocations, mode changes, and full ledger verification
  require an unlocked session. Trust-changing actions also require explicit
  confirmation and an operator reason.

The client assumes the request and response shapes in
`specs/001-codex-memory-firewall/contracts/verity-ipc.openapi.yaml`, including
the exact challenge parameters, status enums, idempotency header, and safe
candidate/detail representations.

## Checks

```bash
npm run typecheck
npm run lint
npm test
npm run build
```
