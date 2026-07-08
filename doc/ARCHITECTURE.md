# SABF implementation notes

This document covers the parts of the implementation that aren't dictated by
[SPEC.md](SPEC.md): module layout, wire format, and decisions the spec left
to the implementer.

## Module layout

```
src/
  main.rs          entry point: env/config load, DB pool, migrations, router, serve
  config.rs        Config::from_env() — all runtime env vars in one place
  error.rs         AppError -> HTTP status/JSON mapping
  state.rs         AppState (pool + config + login rate limiter), Arc-shared
  crypto.rs         server-side crypto only (see below)
  models.rs        sqlx::FromRow row structs mirroring the schema
  repository.rs    + repository/{users,sessions,apps,apps_access,apps_data,audit}.rs
                     one file per table, sqlx::query!/query_as! only (compile-time checked)
  service.rs       + service/{auth,users,apps,data,shares,rate_limiter}.rs
                     business logic: multi-step transactions, authorization checks
  api.rs           + api/{auth,users,apps,data,shares,extractors,bytes}.rs
                     axum handlers, request/response DTOs, router assembly
migrations/
  0001_init.sql    single migration, schema verbatim from SPEC.md §4
```

`repository` functions take either `&PgPool` or a generic `impl PgExecutor<'_>`
(the latter when the service layer needs to run them inside a transaction
alongside other writes — e.g. app creation, metadata PATCH + last_edit_at
bump, and DEK rotation).

## crypto.rs — what the server actually does

Per SPEC.md §1, the server is ciphertext-blind: it never sees a DEK, UMK,
private key, or passphrase-derived key. That means `crypto.rs` does **not**
contain XChaCha20-Poly1305 or X25519 sealed-box code — there's nothing for
the server to encrypt or decrypt. What's left:

- `hash_auth_key` / `verify_auth_key` — the server-side Argon2id verifier
  (`auth_hash = Argon2id(auth_key, auth_salt)`, SPEC.md §3).
- `current_kdf_params` — the fixed, framework-wide Argon2id cost constants
  handed to clients for their own passphrase stretching (SPEC.md §7).
- `encode_access_token` / `decode_access_token` — HS256 JWTs.
- `generate_refresh_token` / `hash_refresh_token` — opaque refresh tokens,
  stored only as a SHA-256 hash.

## Wire format

All binary fields (ciphertext, keys, sealed boxes) are standard base64
strings in JSON, via the `api::bytes::B64` newtype
(`Serialize`/`Deserialize` wrapping `Vec<u8>`). Timestamps are RFC 3339
(`chrono::DateTime<Utc>`'s default serde format).

## Pagination cursor

SPEC.md §5 specifies keyset pagination on `(created_at, id)` with an opaque
`cursor`. This implementation encodes the cursor as
`base64url(json({"created_at": ..., "id": ...}))` — opaque to clients as
required, but human-inspectable for debugging. `GET /apps/:id/data` returns
`next_cursor` (null once the page is short of `limit`) so clients don't have
to compute it themselves.

## CORS

`api::router` attaches a `tower_http::cors::CorsLayer` built from
`config.cors_allowed_origins` (`CORS_ALLOWED_ORIGINS` env var, `config.rs`):
either `*` (any origin, via `AllowOrigin::any()`) or a comma-separated exact
origin list (`AllowOrigin::list(...)`). Allowed methods are
GET/POST/PATCH/DELETE/OPTIONS; allowed headers are `authorization` and
`content-type` (all this API needs — auth is bearer-token, not cookie-based,
so no `allow_credentials`). If unset, the list is empty and no cross-origin
requests are permitted.

## Login rate limiting

In-memory sliding-window counter (`service::rate_limiter::RateLimiter`),
keyed separately by `user:<username>` and `ip:<addr>` (SPEC.md §7). This is
single-instance only, which matches the self-hosted deployment model the
spec assumes; it resets on restart and does not coordinate across replicas.

## Refresh token reuse detection

A session row is created per login/refresh with an optional `parent_id`
pointing at the session it rotated from. Presenting a refresh token whose
session is already `revoked_at IS NOT NULL` (either because it was rotated
away or explicitly logged out) revokes the **entire** lineage — walked via a
recursive CTE over `parent_id` in both directions — per SPEC.md §6.

## Account/app deletion

`DELETE /users/me` and `DELETE /apps/:id` do essentially no manual cascade
logic in Rust: the schema's `ON DELETE CASCADE` foreign keys handle
sessions, owned apps, their `apps_data`/`apps_access` rows, and the
deleted user's own access rows on apps they don't own. The service layer's
job is just the passphrase/ownership check before issuing the `DELETE`.

## Running locally

```
docker compose up -d           # postgres, per compose.yaml
cp .env.example .env           # already done in this repo; edit JWT_SECRET etc.
sqlx migrate run               # applies migrations/0001_init.sql
cargo run
```

`sqlx::query!`/`query_as!` are compile-time checked against a live database
(`DATABASE_URL` from `.env`, loaded by `dotenvy` at both build and run time),
so the Postgres container needs to be up before `cargo build`.
