# Secure Apps Backend Framework (SABF) — Spec v0.1

A self-hostable Rust backend crate providing authentication, app data storage, and
zero-knowledge encryption for any frontend that wants secure, shareable, per-app
storage without trusting the server with plaintext.

## 1. Design principles

- **Zero-knowledge**: the server never sees a passphrase, a KEK, a User Master Key
  (UMK), a private key, or a Data Encryption Key (DEK) in plaintext. It only ever
  stores/serves ciphertext and wrapped keys.
- **No recovery**: losing the passphrase means permanent loss of access to all
  encrypted data for that user. This is the accepted tradeoff of true
  zero-knowledge encryption (same model as Bitwarden's default). Frontends must
  communicate this clearly to end users.
- **One wrapping mechanism, not two**: every app's DEK is sealed individually to
  each user who has access (owner included) via that user's own X25519 public
  key. Ownership and sharing are the same mechanism — a row in `apps_access` with a
  sealed copy of the DEK. There is no separate "owner wraps with UMK" path.
- **Client does all crypto.** The server is ciphertext-blind and orchestration-only.
  Key derivation, encryption, decryption, and re-encryption (e.g. on revoke) all
  happen client-side.

## 2. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Passphrase stretching | Argon2id (per-user random salt, tunable cost params stored server-side) |
| Symmetric encryption (DEK, UMK wrapping) | XChaCha20-Poly1305 (24-byte random nonce, safe to generate randomly at volume) |
| Asymmetric key wrapping (DEK → user) | X25519 sealed boxes (ephemeral-key + XSalsa20-Poly1305, libsodium-style) |
| Login verifier hashing | Argon2id over the `auth_key` half of the stretched passphrase |

Ciphertext encoding convention: every encrypted blob is stored as
`nonce (24B) || ciphertext || auth_tag`, i.e. self-contained — no separate nonce
column per encrypted field.

## 3. Key hierarchy

```
passphrase
   │  Argon2id(passphrase, per-user salt, kdf_params)
   ▼
64 bytes ──► auth_key (32B)  ──Argon2id──► auth_hash (stored server-side, login verifier)
        └──► kek (32B)  (never leaves client)
                   │
                   │ unwraps
                   ▼
         User Master Key (UMK) ── random 32B, generated at signup,
         │                        stored server-side as wrapped_umk = Enc(kek, UMK)
         │ unwraps
         ▼
   X25519 private key ── stored server-side as wrapped_privkey = Enc(UMK, privkey)
                          (public key stored in plaintext, it's not secret)
```

Per app:

```
DEK (random 32B, generated client-side at app creation)
   │
   ├─► sealed_box(owner_pubkey, DEK)    → apps_access row, granted_by=NULL     (owner)
   ├─► sealed_box(granteeA_pubkey, DEK) → apps_access row, granted_by=<owner>  (shared)
   └─► sealed_box(granteeB_pubkey, DEK) → apps_access row, granted_by=<owner>  (shared)

DEK encrypts: apps.encrypted_metadata (single shared value) + every apps_data.encrypted_json
```

**Passphrase change**: only `wrapped_umk` (and the auth_hash/salt) need updating.
No app data or app-level keys are touched, since the UMK itself doesn't change —
only what wraps it.

**Sharing**: owner's client decrypts its own copy of the DEK (via its sealed box),
re-wraps that same raw DEK to the recipient's public key, submits it as a
`status='pending'` row. Recipient's client, on accept, can decrypt with their
private key — no owner interaction needed post-share.

**Revocation**: owner's client generates a *new* DEK, downloads and decrypts all
`apps_data` rows and every remaining grantee's metadata under the old DEK,
re-encrypts everything under the new DEK, creates a new `apps` row with new
`apps_access` memberships (same `slug`, sealed to the new DEK) for every user who
should keep access — excluding the revoked user — then deletes the old app. The
`app_id` changes on every revocation, but `slug` carries over, so a frontend doing
`GET /apps?slug=notes` keeps working transparently without needing to track the
old `app_id`.

## 4. Database schema

```sql
CREATE TABLE users (
    id                UUID PRIMARY KEY,                 -- UUIDv7
    username          TEXT UNIQUE NOT NULL,
    auth_hash         TEXT NOT NULL,                     -- Argon2id(auth_key)
    kdf_salt          BYTEA NOT NULL,
    kdf_params        JSONB NOT NULL,                     -- {mem_cost, time_cost, parallelism, version}
    wrapped_umk       BYTEA NOT NULL,                     -- Enc(kek, UMK)
    public_key        BYTEA NOT NULL,                     -- X25519 pubkey, plaintext
    wrapped_privkey    BYTEA NOT NULL,                     -- Enc(UMK, X25519 privkey)
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id                  UUID PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash  TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ
);

-- The app itself: identity + content shared by everyone with access.
-- Both slug and encrypted_metadata are encrypted/keyed with the app's DEK-level
-- concerns (slug is plaintext by design, metadata is Enc(DEK, ...)) but neither
-- is per-user: anyone holding the DEK decrypts the same metadata. No owner_id:
-- ownership is expressed as the apps_access row with granted_by IS NULL.
CREATE TABLE apps (
    id                  UUID PRIMARY KEY,                 -- UUIDv7
    slug                TEXT NOT NULL,                    -- plaintext, developer-defined app-type
                                                            -- identifier (e.g. "notes"), NOT a
                                                            -- user-editable display name
    encrypted_metadata  BYTEA NOT NULL,                   -- Enc(DEK, {name, settings, ...}), single
                                                            -- shared value, editable by any active member
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Membership + access only (identity/content lives in `apps`)
CREATE TABLE apps_access (
    app_id              UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek         BYTEA NOT NULL,                   -- sealed_box(user's pubkey, DEK)
    status              TEXT NOT NULL CHECK (status IN ('pending','active')) DEFAULT 'active',
    granted_by          UUID REFERENCES users(id),        -- NULL = owner's own row;
    last_access_at      TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, user_id)
);
-- Exactly one owner (granted_by IS NULL) per app
CREATE UNIQUE INDEX idx_apps_access_one_owner ON apps_access(app_id) WHERE granted_by IS NULL;

CREATE TABLE apps_data (
    id              UUID PRIMARY KEY,                    -- UUIDv7, time-ordered
    app_id          UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,                        -- plaintext, queryable/segmentable
    encrypted_json  BYTEA NOT NULL,                        -- Enc(DEK, json)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    edited_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_apps_data_app_type ON apps_data(app_id, type, created_at);
```

## 5. Endpoints

```
Auth
  POST   /auth/register              { username, auth_hash, kdf_salt, kdf_params,
                                        wrapped_umk, public_key, wrapped_privkey }
  POST   /auth/login                 { username, auth_hash }
                                      -> { access_token, refresh_token, kdf_salt,
                                           kdf_params, wrapped_umk, wrapped_privkey, public_key }
  POST   /auth/refresh               { refresh_token } -> { access_token }
  POST   /auth/logout                { refresh_token }
  POST   /auth/change-passphrase     { new_auth_hash, new_kdf_salt, new_kdf_params, new_wrapped_umk }

Users
  GET    /users/me
  GET    /users/:username            -> { user_id, public_key, kdf_salt, kdf_params }
                                      -- unauthenticated, used both pre-login (to derive
                                      -- auth_key/kek) and to initiate a share (need
                                      -- user_id + public_key of the recipient).
                                      -- For unknown usernames, returns deterministic
                                      -- fake-but-plausible values for ALL fields
                                      -- (derived via HMAC(server_secret, username)),
                                      -- so the response shape/timing never reveals
                                      -- whether the username is registered.

Apps
  GET    /apps                       -> [{ app_id, slug, encrypted_metadata, granted_by, status,
                                            wrapped_dek, last_access_at }]
                                      -- granted_by=null means the caller owns this app
                                      -- joins apps + the caller's apps_access row
  GET    /apps?slug=notes            -- direct fetch by slug (scoped to the caller's own
                                      -- active apps), skips listing+client-side search
  POST   /apps                       { slug, encrypted_metadata, wrapped_dek } -> app + owner row
  GET    /apps/:id                   -> { slug, encrypted_metadata, wrapped_dek, granted_by, status }
  PATCH  /apps/:id                   { encrypted_metadata }  -- any active member (owner or shared);
                                      -- last-write-wins, no conflict resolution (slug is
                                      -- set at creation and immutable)
  DELETE /apps/:id                   -- owner only, cascades to apps_access + apps_data

App data
  POST   /apps/:id/data              { type, encrypted_json } -> row
  GET    /apps/:id/data?type=&from=&to=&limit=&cursor=
  PATCH  /apps/:id/data/:data_id     { encrypted_json }        -- bumps edited_at
  DELETE /apps/:id/data/:data_id

Sharing
  POST   /apps/:id/shares            { recipient_user_id, wrapped_dek } -> pending row
  GET    /apps/:id/shares            -- owner: list grantees + pending invites
  GET    /shares/pending             -- current user's incoming pending shares
  POST   /shares/:app_id/accept
  POST   /shares/:app_id/decline
  DELETE /apps/:id/shares/:user_id   -- owner-initiated revoke; client performs the
                                      -- rotate-DEK-and-recreate-app flow (§3) and the
                                      -- app_id returned to the frontend changes
```

## 6. Open items for v0.2

- Rate limiting / brute-force protection on `/auth/login` (Argon2id cost alone
  isn't sufic — need lockout or backoff policy).
- Multi-device: current design supports it (any device re-derives KEK from the
  same passphrase+salt and unwraps the same UMK), but device-level session
  management/listing isn't specced yet.
- Audit logging of share/revoke events (metadata only — server can log "user X
  shared app Y with user Z at time T" without touching plaintext).
- Pagination cursor format for `GET /apps/:id/data`.
- Whether `apps_data.type` values should be namespaced/validated against an
  allowlist per app, or left freeform.
- `server_secret` (HMAC key for deterministic fake values in `GET /users/:username`
  for unknown usernames) needs a storage/rotation story — rotating it changes the
  fake values returned, which is harmless, but the secret must never be exposed.
- `user_id` is now returned by an unauthenticated endpoint (`GET /users/:username`).
  UUIDv7 ids are already unguessable, so this doesn't materially aid enumeration,
  but worth confirming that's an acceptable exposure for a self-hosted deployment.
- Since `slug` now lives on `apps` (not `apps_access`), "one active app per slug per
  user" can no longer be a single-table partial unique index — it spans a join.
  Needs either an application-level check-then-insert, or a trigger, to stay
  race-free under concurrent app creation.
- `encrypted_metadata` is now shared and any active member can PATCH it with no
  conflict resolution (last write wins) — fine for casual use, but a concurrent-edit
  story (versioning/ETag on PATCH) may be worth adding if apps end up being
  actively co-edited rather than mostly read.
