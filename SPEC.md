# Secure Apps Backend Framework (SABF) — Spec v0.2

A self-hostable Rust backend crate providing authentication, app data storage, and
zero-knowledge encryption for any frontend that wants secure, shareable, per-app
storage without trusting the server with plaintext.

## 1. Design principles

- **Zero-knowledge (for content)**: the server never sees a passphrase, a KEK, a
  User Master Key (UMK), a private key, or a Data Encryption Key (DEK) in plaintext.
  It only ever stores/serves ciphertext and wrapped keys.
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
  happen client-side. The client also generates all resource UUIDs (`apps.id`,
  `apps_data.id`) so it can bind them into ciphertext AAD before upload (§2).

### 1.1 Trust model (read this before calling it "zero-knowledge")

Confidentiality of **content** (app metadata + app data) does not depend on trusting
the server. Everything else does. Specifically, a malicious or compromised server can:

- Substitute its own X25519 public key in `GET /users/:username` and MITM any
  subsequent share (sealed boxes provide no sender authentication).
- Fabricate pending shares — `role`/membership rows are server-asserted, and sealed
  boxes are anonymous by design, so a client cannot prove who sealed a DEK to it.
- Serve stale ciphertext, drop writes, or lie about membership.
- Downgrade KDF parameters at login (mitigated by a client-side floor, §7).

This is the same residual trust surface Bitwarden has, and it is acceptable for a
self-hosted deployment where the operator and the user are the same party or trust
each other. **Metadata, membership, and public-key distribution are trusted-server;
only content confidentiality is not.**

## 2. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Passphrase stretching (client-side) | Argon2id (per-user random salt, **fixed framework cost params**, see §7) |
| Symmetric encryption (DEK, UMK, privkey wrapping) | XChaCha20-Poly1305 (24-byte random nonce, safe to generate randomly at volume) with AAD binding |
| Asymmetric key wrapping (DEK → user) | X25519 sealed boxes (ephemeral-key + XSalsa20-Poly1305, libsodium-style) |
| Login verifier hashing (server-side) | Argon2id over the client-supplied `auth_key`, with a per-user server-side salt |

Ciphertext encoding convention: every encrypted blob is stored as
`nonce (24B) || ciphertext || auth_tag`, i.e. self-contained — no separate nonce
column per encrypted field.

### 2.1 AAD binding

Every content ciphertext is encrypted with Additional Authenticated Data that ties
it to its logical location. AAD is authenticated but **not** stored — it is
recomputed from row identity at decrypt time, and a mismatch makes decryption fail.
This prevents an attacker with DB write access from relocating a valid ciphertext
into a different row (copy/paste, cross-app splicing, `type` rewriting).

| Encrypted field | AAD (canonical byte encoding of the tuple) |
|---|---|
| `apps.encrypted_metadata` | `(app_id, "metadata")` |
| `apps_data.encrypted_json` | `(app_id, data_id, type)` |
| `users.wrapped_umk` | `(user_id, "umk")` |
| `users.wrapped_privkey` | `(user_id, "privkey")` |

Because `type` is part of the data-row AAD, **`type` is immutable** after creation
(a PATCH may only change `encrypted_json`). Because `app_id`/`data_id` are part of
the AAD, the client must know them before encrypting — hence client-generated UUIDs.

## 3. Key hierarchy

```
passphrase
   │  Argon2id(passphrase, per-user kdf_salt, fixed params)
   ▼
64 bytes ──► auth_key (32B)  ── sent to server; server stores
        │                       auth_hash = Argon2id(auth_key, per-user auth_salt)
        │                       (the wire value never equals the stored verifier)
        │
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

**Login verifier — why the split matters.** The client sends `auth_key` (never
`auth_hash`). The server applies its *own* Argon2id (`auth_hash =
Argon2id(auth_key, auth_salt)`) before storing/comparing. Consequently the stored
verifier is never equal to anything that travels on the wire, so a database dump
does not yield a login credential (no pass-the-hash). `kek` is derived from the same
64 bytes but is a different half and never leaves the client, so the server learns
nothing about the wrapping key.

Per app:

```
DEK (random 32B, generated client-side at app creation)
   │
   ├─► sealed_box(owner_pubkey, DEK)    → apps_access row, role='owner'   (owner)
   ├─► sealed_box(granteeA_pubkey, DEK) → apps_access row, role='member'  (shared)
   └─► sealed_box(granteeB_pubkey, DEK) → apps_access row, role='member'  (shared)

DEK encrypts: apps.encrypted_metadata (single shared value) + every apps_data.encrypted_json
```

**Passphrase change**: only `wrapped_umk` (and `auth_hash`/`auth_salt`/`kdf_salt`)
need updating. No app data or app-level keys are touched, since the UMK itself
doesn't change — only what wraps it. The endpoint **requires proof of the current
passphrase** (the client sends the current `auth_key`, which the server verifies)
and revokes all other sessions on success, so a stolen access token alone cannot be
used to overwrite `wrapped_umk` and permanently destroy the account.

**Sharing** (owner-only in v0.2): owner's client decrypts its own copy of the DEK
(via its sealed box), re-wraps that same raw DEK to the recipient's public key,
submits it as a `status='pending'` row. Recipient's client, on accept, decrypts with
their private key — no owner interaction needed post-share.

> **Pending is a cryptographic grant, not a social one.** The `wrapped_dek` in a
> pending row is sealed to the recipient at creation, so the recipient can decrypt
> it the instant the row exists. As defense-in-depth the server does **not** serve
> `wrapped_dek` on the pending-list endpoint — only in the accept response — so an
> honest server never hands the sealed DEK to a recipient who declines. This is a
> layer, not a guarantee: a malicious server (or one whose DB leaks) could still
> surface it. Therefore an owner who cancels/declines a pending share they no longer
> want honored should treat the DEK as potentially exposed and rotate (§3.1) to be
> strict.

### 3.1 DEK rotation (revocation) — atomic, in place

Revocation and any "the DEK might be exposed" event are handled by a single
server-side transactional endpoint, **not** by recreating the app. The owner's
client:

1. Decrypts the current DEK, generates a **new** DEK.
2. Downloads and decrypts all `apps_data` rows and the metadata under the old DEK,
   re-encrypts each under the new DEK (recomputing AAD, unchanged since ids are
   stable).
3. Seals the new DEK to every user who should keep access (excluding the revoked
   user).
4. `POST /apps/:id/rotate` submits `{ new_encrypted_metadata,
   data: [{ id, new_encrypted_json }], access: [{ user_id, new_wrapped_dek }] }`.

The server applies it in **one transaction**: overwrite metadata, overwrite each
listed data row's ciphertext, replace the `apps_access` wrapped_dek set with exactly
the submitted list (dropping any omitted user), all keyed on the stable `app_id`.

Rotating in place (rather than the old "recreate the app under a new `app_id`,
carry the slug over" scheme) fixes several problems at once:

- **Atomicity**: no window where two apps share a slug or a half-migrated app loses
  data to a client crash.
- **No lost writes**: the transaction fails and retries if a concurrent write lands
  (optimistic — the server compares the data-row set / a rotation counter); nothing
  is silently dropped between "download" and "delete".
- **Stable identity**: `app_id`, every `data_id`, and all `created_at`/`edited_at`
  timestamps survive, so history is preserved and no slug-carryover workaround is
  needed.

Two properties to state to frontends: revocation is **forward-only** (a revoked user
may already have copied plaintext; rotation only stops *future* reads), and any
pending share sealed to the *old* DEK must be cancelled and re-issued after a
rotation.

For very large apps a staged two-phase rotate (upload re-encrypted chunks, then
commit) may be added later; v0.2 assumes the payload fits one request.

## 4. Database schema

```sql
CREATE TABLE users (
    id                UUID PRIMARY KEY,                 -- UUIDv7
    username          TEXT UNIQUE NOT NULL,
    auth_hash         TEXT NOT NULL,                     -- Argon2id(auth_key, auth_salt), server-side
    auth_salt         BYTEA NOT NULL,                     -- per-user, server-side verifier salt
    kdf_salt          BYTEA NOT NULL,                     -- per-user, client-side passphrase salt
    kdf_params        JSONB NOT NULL,                     -- server-set fixed params + version (§7)
    wrapped_umk       BYTEA NOT NULL,                     -- Enc(kek, UMK), AAD=(user_id,"umk")
    public_key        BYTEA NOT NULL,                     -- X25519 pubkey, plaintext
    wrapped_privkey   BYTEA NOT NULL,                     -- Enc(UMK, privkey), AAD=(user_id,"privkey")
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id                  UUID PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash  TEXT NOT NULL,                    -- SHA-256 of the opaque refresh token
    parent_id           UUID REFERENCES sessions(id),     -- rotation lineage, for reuse detection
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ
);

-- The app itself: identity + content shared by everyone with access.
-- slug is a plaintext app-TYPE identifier (which frontend/UI loads this data);
-- it is NOT unique and NOT a display name. metadata is Enc(DEK, ...), one shared
-- value for all members.
CREATE TABLE apps (
    id                  UUID PRIMARY KEY,                 -- UUIDv7, client-generated
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug                TEXT NOT NULL,                    -- plaintext app-type id (e.g. "notes"),
                                                            -- NOT unique, NOT a user-editable name
    encrypted_metadata  BYTEA NOT NULL,                   -- Enc(DEK, {name, settings, ...}),
                                                            -- AAD=(app_id,"metadata"); any active member edits
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_apps_owner ON apps(owner_id);

-- Membership + access only (identity/content lives in `apps`)
CREATE TABLE apps_access (
    app_id              UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek         BYTEA NOT NULL,                   -- sealed_box(user's pubkey, DEK)
    role                TEXT NOT NULL CHECK (role IN ('owner','member')) DEFAULT 'member',
    status              TEXT NOT NULL CHECK (status IN ('pending','active')) DEFAULT 'active',
    last_edit_at        TIMESTAMPTZ,                      -- bumped on this user's writes (§5)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, user_id)
);
-- Exactly one owner row per app; must match apps.owner_id.
CREATE UNIQUE INDEX idx_apps_access_one_owner ON apps_access(app_id) WHERE role = 'owner';

CREATE TABLE apps_data (
    id              UUID PRIMARY KEY,                    -- UUIDv7, client-generated, time-ordered
    app_id          UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,                        -- plaintext, freeform, immutable, queryable
    encrypted_json  BYTEA NOT NULL,                       -- Enc(DEK, json), AAD=(app_id,data_id,type)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    edited_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_apps_data_app_type ON apps_data(app_id, type, created_at);
CREATE INDEX idx_apps_data_app_created ON apps_data(app_id, created_at);

-- Metadata-only audit trail (no plaintext ever). See §8.
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,                        -- 'share','accept','decline','revoke',
                                                            -- 'rotate','leave','app.delete', ...
    app_id          UUID,
    target_user_id  UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Notes:
- **Ownership** is authoritative on `apps.owner_id` and mirrored by the
  `role='owner'` access row (which holds the owner's own sealed DEK). Deleting a
  user cascades to the apps they own (see `DELETE /users/me`, §5).
- **Slug is not unique** in any scope. The same frontend may hold many independent
  app instances of the same slug (e.g. copies). `GET /apps?slug=notes` returns an
  array.

## 5. Endpoints

All authenticated endpoints take `Authorization: Bearer <access_token>` (a JWT, §6).

```
Auth
  POST   /auth/register              { username, auth_key, kdf_salt,
                                        wrapped_umk, public_key, wrapped_privkey }
                                      -- server generates auth_salt, computes
                                      --   auth_hash = Argon2id(auth_key, auth_salt),
                                      --   sets kdf_params to the fixed framework value.
                                      -- 409 if username taken (existence is not hidden, §7).
  POST   /auth/login                 { username, auth_key }
                                      -> { access_token, refresh_token, kdf_salt,
                                           kdf_params, wrapped_umk, wrapped_privkey, public_key }
                                      -- rate-limited (§7).
  POST   /auth/refresh               { refresh_token } -> { access_token, refresh_token }
                                      -- rotates the refresh token; reuse of a consumed
                                      --   token revokes the whole lineage.
  POST   /auth/logout                { refresh_token }   -- revokes that session
  POST   /auth/change-passphrase     { current_auth_key, new_auth_key, new_kdf_salt,
                                        new_wrapped_umk }
                                      -- verifies current_auth_key; on success re-derives
                                      --   auth_hash (new auth_salt), updates wrapped_umk,
                                      --   revokes all OTHER sessions.

Users
  GET    /users/me                   -> { user_id, username, public_key, created_at }
  GET    /users/:username            -> { user_id, public_key, kdf_salt, kdf_params }
                                      -- unauthenticated (login needs kdf_salt before a
                                      --   session exists). 404 for unknown users; existence
                                      --   is intentionally NOT hidden (§7). Used pre-login
                                      --   and to look up a share recipient.
  DELETE /users/me                   { current_auth_key }
                                      -- verifies passphrase; cascades: deletes apps the user
                                      --   OWNS (+ their data + all grantee access), removes
                                      --   the user from apps shared with them, revokes all
                                      --   sessions. Frontends MUST warn that owned shared apps
                                      --   are destroyed for everyone.

Apps
  GET    /apps                       -> [{ app_id, slug, encrypted_metadata, role, status,
                                            wrapped_dek, last_edit_at }]
                                      -- caller's active memberships joined with apps.
                                      -- wrapped_dek omitted for pending rows.
  GET    /apps?slug=notes            -- same shape, filtered to the caller's active apps of
                                      --   that slug (may return multiple).
  POST   /apps                       { app_id, slug, encrypted_metadata, wrapped_dek }
                                      -> app + owner access row (role='owner', status='active')
  GET    /apps/:id                   -> { slug, encrypted_metadata, wrapped_dek, role, status }
                                      -- active members only; pending members get 403.
  PATCH  /apps/:id                   { encrypted_metadata }
                                      -- any ACTIVE member; last-write-wins in a transaction.
                                      --   Frontends MUST read-before-write; the transaction
                                      --   makes a lost update rare. slug is immutable.
  POST   /apps/:id/rotate            { new_encrypted_metadata, data:[{id,new_encrypted_json}],
                                        access:[{user_id,new_wrapped_dek}] }
                                      -- OWNER only. Atomic DEK rotation / revocation (§3.1).
  DELETE /apps/:id                   -- OWNER only, cascades to apps_access + apps_data.
  POST   /apps/:id/leave             -- a non-owner member removes their OWN access row.
                                      --   No DEK rotation (see §3.1 forward-only note); the
                                      --   owner should rotate if true revocation is needed.

App data
  POST   /apps/:id/data              { data_id, type, encrypted_json } -> row
                                      -- active members only; bumps caller's last_edit_at.
  GET    /apps/:id/data?type=&created_from=&created_to=&edited_from=&edited_to=&limit=&cursor=
                                      -- active members only. Filters on any non-encrypted
                                      --   field; keyset pagination (below).
  PATCH  /apps/:id/data/:data_id     { encrypted_json }   -- active members; bumps edited_at
                                      --   and caller's last_edit_at. type is immutable.
  DELETE /apps/:id/data/:data_id     -- active members.

Sharing  (owner-only issuance in v0.2)
  POST   /apps/:id/shares            { recipient_user_id, wrapped_dek } -> pending row
  GET    /apps/:id/shares            -- owner: list grantees + pending invites
  GET    /shares/pending             -- caller's incoming pending shares
                                      --   (wrapped_dek is NOT included here, §3)
  POST   /apps/:id/shares/accept     -> { wrapped_dek }   -- flips caller's row to active and
                                      --   returns the sealed DEK
  POST   /apps/:id/shares/decline    -- caller declines; row deleted
  DELETE /apps/:id/shares/:user_id   -- OWNER removes a member's row. For TRUE revocation the
                                      --   owner performs POST /apps/:id/rotate excluding that
                                      --   user (this endpoint alone does not rotate the DEK).
```

**Status semantics.** A `pending` member cannot read or write `/apps/:id/data`,
cannot `PATCH` metadata, does not appear in `GET /apps`, and is not returned a
`wrapped_dek` outside the accept response. Only `active` members have access.

**Pagination.** `GET /apps/:id/data` uses keyset pagination: `cursor` is an opaque
base64 of `(created_at, id)` of the last row seen; `limit` defaults to 50, capped at
e.g. 500; results ordered by `(created_at, id)`. Filters (`type`, `created_from/to`,
`edited_from/to`) apply to plaintext columns only.

**`last_edit_at`** is stored per membership row and updated on that member's writes
(POST/PATCH/DELETE of data, PATCH metadata) — never on reads, so reading never
incurs a write.

## 6. Sessions & tokens

- **Access token**: JWT, HS256, signed with a server secret. Claims: `sub` (user_id),
  `sid` (session id), `iat`, `exp` (~15 min). Stateless; multi-device is inherent —
  any device that re-derives the KEK from the same passphrase+`kdf_salt` unwraps the
  same UMK, and each device holds its own session/JWT.
- **Refresh token**: opaque 32-byte random, stored only as `refresh_token_hash`
  (SHA-256). Lifetime ~30 days. Rotated on every `/auth/refresh`; the old token is
  marked consumed. **Reuse detection**: presenting an already-consumed refresh token
  revokes the entire session lineage (`parent_id` chain) as a theft signal.
- `change-passphrase` and `DELETE /users/me` revoke sessions as described in §5.

## 7. KDF, rate limiting, enumeration

- **Fixed KDF params.** Client-side Argon2id uses framework-fixed cost parameters
  (a single `{ mem_cost, time_cost, parallelism, version }` constant), with a
  per-user random `kdf_salt`. `kdf_params` is still stored/returned (carrying a
  `version`) so the framework can introduce a *new* fixed set later without locking
  out existing users, but clients never choose it. Clients MUST refuse to derive
  with params below a hard floor, defending against a malicious server advertising
  downgraded costs at login. Server-side verifier hashing (`auth_hash`) likewise
  uses fixed Argon2id params with a per-user `auth_salt`.
- **Login rate limiting.** `POST /auth/login` is capped at a small number of attempts
  (e.g. 10) per rolling one-minute window, keyed by username and by source IP;
  excess returns `429`. This is the brute-force backstop Argon2id cost alone doesn't
  provide.
- **Enumeration: explicitly not defended.** v0.2 drops the deterministic-fake-user
  scheme. `POST /auth/register` (409 on taken), `GET /users/:username` (404 on
  unknown), and share lookups all reveal whether a username/user exists. For a
  self-hosted deployment this is an accepted tradeoff for simplicity, and with open
  registration it's unavoidable anyway. There is no `server_secret` for fake values.
  `user_id` (UUIDv7) is exposed by `GET /users/:username`; v7 embeds a 48-bit
  creation timestamp (so it leaks *when* an account/resource was created) but retains
  ~74 random bits, so ids remain impractical to guess — acceptable for self-hosting.

## 8. Audit logging

Share, accept, decline, revoke, rotate, leave, and app-delete events are recorded in
`audit_log` with actor, action, `app_id`, and (where relevant) target user and
timestamp — metadata only, never plaintext. E.g. "user X shared app Y with user Z at
time T." Useful for operators without weakening zero-knowledge of content.

## 9. Edge cases

- When deleting an account, the app dies with the owner. There is no ownership transfer system.
- Non-owner re-sharing: owner-only issuance to keep revocation tractable.
- The JWT signing secret is an environment variable key. If absent, a random key is generated at each start.
