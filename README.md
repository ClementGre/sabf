# SABF — Simple Application Backend Framework

A self-hostable Rust backend that gives any frontend **authentication, per-app
data storage, sharing, and zero-knowledge encryption** — without ever trusting
the server with plaintext.

The server is *ciphertext-blind*: it never sees a passphrase, a master key, a
private key, or a per-app data key. It stores and serves only ciphertext and
wrapped keys. All cryptography (key derivation, encryption, decryption,
re-encryption on revoke) happens in the client. The server does authentication,
authorization, storage, and share orchestration — nothing that requires reading
your data.

> **No recovery.** True zero-knowledge means losing your passphrase permanently
> loses access to all encrypted data for that account — the same tradeoff as
> Bitwarden's default. Frontends must communicate this to end users.

- 📖 **[doc/SPEC.md](doc/SPEC.md)** — the protocol: crypto primitives, key
  hierarchy, database schema, endpoints, trust model.
- 🏗️ **[doc/ARCHITECTURE.md](doc/ARCHITECTURE.md)** — implementation notes:
  module layout, wire format, and decisions the spec left open.
- 🧩 **[example/vuejs-front](example/vuejs-front/README.md)** — a minimal
  reference client (Vue + Vite + Tailwind) doing all crypto in the browser.

## Features

- **Zero-knowledge content encryption.** App metadata and app data are
  encrypted client-side under a per-app Data Encryption Key (DEK). The server
  stores only `nonce || ciphertext || tag` blobs bound to their row via AAD, so
  an attacker with DB write access can't relocate a valid ciphertext into a
  different row.
- **One wrapping mechanism for ownership *and* sharing.** Each app's DEK is
  sealed individually to every user who has access (owner included) via that
  user's X25519 public key. Sharing is just another sealed copy of the same DEK.
- **Split login verifier.** The client derives an `auth_key` and a `kek` from
  the passphrase; only `auth_key` is sent, and the server re-hashes it with its
  own Argon2id + per-user salt. The stored verifier never equals anything on the
  wire, so a database dump yields no login credential (no pass-the-hash).
- **Atomic DEK rotation / revocation.** `POST /apps/:id/rotate` re-wraps a new
  DEK to the remaining members and overwrites all ciphertext in a single
  transaction — stable `app_id`, no half-migrated state, no slug carryover.
- **Session security.** Short-lived HS256 access tokens (~15 min) + rotating
  opaque refresh tokens (stored only as SHA-256 hashes) with reuse detection
  that revokes the whole session lineage on a replayed token.
- **Login rate limiting** (per-username and per-IP sliding window) and a
  **metadata-only audit log** (shares, accepts, revokes, rotations — never
  plaintext).

See [doc/SPEC.md §1.1](doc/SPEC.md) for the honest trust model: content
confidentiality does **not** depend on trusting the server; metadata,
membership, and public-key distribution do.

## Tech stack

- **Rust** (edition 2024), [axum](https://github.com/tokio-rs/axum) HTTP,
  [sqlx](https://github.com/launchbadge/sqlx) with compile-time-checked queries
- **PostgreSQL** (single migration, schema verbatim from the spec)
- **Argon2id**, **HS256 JWT**, **SHA-256** server-side; the heavy crypto
  (XChaCha20-Poly1305, X25519 sealed boxes) lives entirely in the client

## Quick start

### With Docker Compose

Brings up PostgreSQL, the backend, and the example frontend:

```sh
cp .env.example .env          # then set JWT_SECRET (openssl rand -base64 48)
docker compose up -d --build
```

- Backend API → http://localhost:8080
- Example frontend → http://localhost:80

### From source

Requires a running Postgres and the [sqlx CLI](https://crates.io/crates/sqlx-cli).
Because queries are compile-time checked against a live database, Postgres must
be up before `cargo build`.

```sh
docker compose up -d postgres   # or point DATABASE_URL at your own Postgres
cp .env.example .env            # edit JWT_SECRET etc.
sqlx migrate run                # applies migrations/0001_init.sql
cargo run
```

Health check: `GET /health` → `{"status":"healthy","service":"sabf"}`.

## Configuration

All runtime configuration is via environment variables (loaded from `.env` in
development). See [.env.example](.env.example) for the full list; the essentials:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — (required) | Postgres connection string |
| `HOST` / `PORT` | `0.0.0.0` / `80` | Bind address |
| `JWT_SECRET` | random per-start | HS256 signing secret; **must be ≥ 32 bytes**. If unset, a random secret is generated each start (invalidating existing tokens on restart) |
| `ACCESS_TOKEN_TTL_SECS` | `900` | Access-token lifetime (~15 min) |
| `REFRESH_TOKEN_TTL_SECS` | `2592000` | Refresh-token lifetime (~30 days) |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | `10` | Login attempts per window (per user & per IP) |
| `LOGIN_RATE_LIMIT_WINDOW_SECS` | `60` | Rate-limit window |
| `CLIENT_IP_HEADER` | unset | Header carrying the real client IP behind a trusted reverse proxy (e.g. `X-Forwarded-For`). Leave unset when directly exposed — a client-supplied header is spoofable |
| `CORS_ALLOWED_ORIGINS` | unset | `*` (any origin) or a comma-separated exact-origin allow-list. Unset = no cross-origin requests |

## Project layout

```
src/            Rust backend (main, config, error, state, crypto, models,
                repository/, service/, api/)  — see doc/ARCHITECTURE.md
migrations/     0001_init.sql — full schema from doc/SPEC.md §4
doc/            SPEC.md (protocol) + ARCHITECTURE.md (implementation notes)
example/        vuejs-front — reference client, all crypto in-browser
Dockerfile      multi-stage: builder → prod (and a dev target)
compose.yaml    postgres + backend + example frontend
```

## Writing a frontend

SABF is a backend framework; the client owns all cryptography. The
[example frontend](example/vuejs-front/README.md) is the reference — its
`lib/crypto.js` implements SPEC §2/§3 and its `lib/apps.js` gives app components
a plaintext-in / plaintext-out API so the raw DEK never escapes that layer.
Adding a new app is a matter of dropping a component under `src/apps/<slug>/`
and registering it. Read [doc/SPEC.md](doc/SPEC.md) before implementing crypto
in another client — especially the AAD binding rules and the client-side KDF
floor that defends against a malicious server advertising downgraded costs.

## Continuous integration

[`.github/workflows/docker.yml`](.github/workflows/docker.yml) builds and pushes
the multi-stage `prod` backend image to the GitHub Container Registry
(`ghcr.io`) on every push to `main`, with a build provenance attestation:

- `ghcr.io/<owner>/<repo>-back` — the backend

## License

Licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE).
