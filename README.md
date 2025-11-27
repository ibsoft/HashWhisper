# HashWhisper

HashWhisper is a Flask-based, end-to-end encrypted group chat that treats the server as an opaque transport. Clients derive AES-GCM keys locally from a shared secret QR hash; the server only stores ciphertext blobs and minimal metadata.

## Features
- Strong auth: Argon2 password hashing, 2FA (Google Authenticator–compatible). TOTP can be required (`HASHWHISPER_REQUIRE_TOTP=true`) or optional with user-controlled toggle/setup from Settings.
- Hardening defaults: strict CSP (no inline scripts), HSTS, secure cookies, referrer/XFO/XCTO headers, HTTPS-only redirects, session fixation protection, input sanitization/secure filenames, CSRF on all stateful endpoints, lockout + rate limits on login/registration.
- E2EE-first chat: client-side AES-GCM for text/media, per-group key derivation from shared secret hash, replay detection via nonce reuse checks, blockchain-style integrity chain for group membership changes.
- Media safety: client encrypts images/videos/voice before upload; server stores random-named ciphertext blobs only. Authenticated download endpoints, no plaintext at rest. Browser caches encrypted blobs and reuses decrypted media in-memory for faster loads.
- Presence & UX: SSE-powered presence/typing indicators (Redis-backed fanout when configured), modern mobile-first UI with Bootstrap + Font Awesome, dark/light toggle, emoji-friendly chat bubbles, inline likes/dislikes, inline media preview/playback, PWA install prompt, optional sounds.
- Data minimization: messages expire after 7 days; `flask purge-expired` CLI shreds expired ciphertext and blobs. Minimal metadata logged (no content).

## Running locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export HASHWHISPER_SECRET="change-me"  # required in production
# Optional local Postgres/Redis:
# export HASHWHISPER_DATABASE_URI="postgresql+psycopg2://user:pass@localhost:5432/hashwhisper"
# export HASHWHISPER_REDIS_URL="redis://localhost:6379/0"
flask --app wsgi run --debug
```

## Production with Postgres + Redis
- Database: set `HASHWHISPER_DATABASE_URI=postgresql+psycopg2://user:pass@host:5432/hashwhisper`. Apply schema with `flask --app wsgi db upgrade`.
- Migrations are pre-baked in `migrations/`; use `flask --app wsgi db migrate -m "msg"` and `flask --app wsgi db upgrade` for future schema changes.
- Presence + rate limits: set `HASHWHISPER_REDIS_URL=redis://user:pass@host:6379/0` (also used automatically for limiter storage). SSE presence then fans out via Redis pub/sub across workers.
- TLS: terminate with a reverse proxy (nginx/caddy) and keep `Talisman` HTTPS enforcement on. Ensure secure cookies remain enabled.

## Configuration (env vars)
- `HASHWHISPER_SECRET` (required in prod): Flask/Talisman secret.
- `HASHWHISPER_DATABASE_URI`: SQLAlchemy URI (defaults to local sqlite).
- `HASHWHISPER_REDIS_URL`: Redis for presence; also used for rate limiting if set.
- `HASHWHISPER_RATELIMIT_URI`: override limiter storage (falls back to Redis URL or memory).
- `HASHWHISPER_REQUIRE_TOTP` (default `true`): force TOTP for all logins; if `false`, users can toggle/setup TOTP from Settings (QR modal).
- `HASHWHISPER_APP_TITLE`: navbar title text.
- `HASHWHISPER_MAX_UPLOAD`: max encrypted upload size in bytes (default 10 MiB).
- `HASHWHISPER_RETENTION_DAYS`: days before ciphertext/blob purge (default 7).
- `HASHWHISPER_UPLOAD_FOLDER`: encrypted blob storage path (default `app/storage`).

## Security/crypto flow
- Registration requires strong passwords; Argon2 hashes are stored. A random TOTP secret is issued and must be enrolled immediately (or optionally enabled later if TOTP is not required).
- Login flow: password check -> 2FA challenge (if required or enabled) -> session regeneration -> strong session cookies (HTTPOnly, Secure, SameSite=Lax).
- CSP disallows inline code; all scripts/styles are external/static. Talisman forces HTTPS + HSTS.
- Groups: creator supplies a shared secret; the server stores only `blake2b(secret)` for membership checks. A one-time QR payload `{group, secret}` is rendered client-side; users must distribute it out-of-band. A “Suggest” button generates strong secrets; copy is inline. Secret entry is verified server-side to prevent wrong-key joins.
- Key derivation: clients derive an AES-GCM 256-bit key from the shared secret with PBKDF2-SHA256 (120k iterations, salted per group) and encrypt messages/files with AES-GCM + AAD `HashWhisper:v1`. Nonces are random 96-bit; reuse is rejected server-side.
- Storage model: messages persist ciphertext, nonce, auth tag, and minimal meta; media blobs are ciphertext-only files with random names. No plaintext content is stored. IntegrityChain tracks group events with linked SHA-256 hashes to detect tampering.
- Presence: SSE stream uses authenticated sessions; events carry no keys or content.
- Purging: retention defaults to 7 days; invoke `flask --app wsgi purge-expired` to remove expired ciphertext and blobs.
- Media caching: `/api/blob/<id>` responses are cacheable (`private, max-age=3600, immutable`); the client keeps decrypted URLs in-memory to avoid repeat decrypt/download. Plaintext is never persisted.

## Notes
- Always deploy behind TLS termination; HTTPS enforcement is enabled by default.
- Configure `HASHWHISPER_MAX_UPLOAD` to set encrypted upload caps. Only allowlisted MIME types are accepted server-side.
- Avoid storing or transmitting shared secrets through the server beyond the one-time QR render; clients must keep them safe.
- For faster delivery, keep SSE/WebSockets unblocked; polling is currently 10s for background refresh and immediate on send for the sender. Presence and media caching benefit from Redis.
