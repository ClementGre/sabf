-- SABF v0.2 schema — see /app/SPEC.md §4 for design rationale.

CREATE TABLE users (
    id                UUID PRIMARY KEY,                  -- UUIDv7
    username          TEXT UNIQUE NOT NULL,
    auth_hash         TEXT NOT NULL,                      -- Argon2id(auth_key, auth_salt), server-side
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
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);

-- The app itself: identity + content shared by everyone with access.
-- slug is a plaintext app-TYPE identifier (which frontend/UI loads this data);
-- it is NOT unique and NOT a display name. metadata is Enc(DEK, ...), one shared
-- value for all members.
CREATE TABLE apps (
    id                  UUID PRIMARY KEY,                 -- UUIDv7, client-generated
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug                TEXT NOT NULL,                    -- plaintext app-type id (e.g. "notes"),
                                                            -- NOT unique, NOT a user-editable name
    encrypted_metadata  BYTEA NOT NULL,                    -- Enc(DEK, {name, settings, ...}),
                                                            -- AAD=(app_id,"metadata"); any active member edits
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_apps_owner ON apps(owner_id);

-- Membership + access only (identity/content lives in `apps`)
CREATE TABLE apps_access (
    app_id              UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek         BYTEA NOT NULL,                    -- sealed_box(user's pubkey, DEK)
    role                TEXT NOT NULL CHECK (role IN ('owner','member')) DEFAULT 'member',
    status              TEXT NOT NULL CHECK (status IN ('pending','active')) DEFAULT 'active',
    last_edit_at        TIMESTAMPTZ,                       -- bumped on this user's writes (§5)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, user_id)
);
-- Exactly one owner row per app; must match apps.owner_id.
CREATE UNIQUE INDEX idx_apps_access_one_owner ON apps_access(app_id) WHERE role = 'owner';
CREATE INDEX idx_apps_access_user ON apps_access(user_id);

CREATE TABLE apps_data (
    id              UUID PRIMARY KEY,                     -- UUIDv7, client-generated, time-ordered
    app_id          UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,                         -- plaintext, freeform, immutable, queryable
    encrypted_json  BYTEA NOT NULL,                        -- Enc(DEK, json), AAD=(app_id,data_id,type)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    edited_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_apps_data_app_type ON apps_data(app_id, type, created_at);
CREATE INDEX idx_apps_data_app_created ON apps_data(app_id, created_at);

-- Metadata-only audit trail (no plaintext ever). See §8.
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,                         -- 'share','accept','decline','revoke',
                                                            -- 'rotate','leave','app.delete', ...
    app_id          UUID,
    target_user_id  UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
