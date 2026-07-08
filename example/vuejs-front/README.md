# SABF example frontend (Vue + Vite + Tailwind)

A minimal reference client for a SABF backend (see `../../doc/SPEC.md`). All
crypto (Argon2id, XChaCha20-Poly1305, X25519 sealed boxes) happens here in
the browser via `libsodium-wrappers-sumo` — the backend never sees
plaintext, DEKs, or the UMK.

## Running

```
npm install
npm run dev
```

Point it at a running backend via `.env`:

```
VITE_API_BASE_URL=http://localhost:8080
```

The backend must allow this origin in `CORS_ALLOWED_ORIGINS` (see
`../../doc/ARCHITECTURE.md`).

## Layout

```
src/
  lib/
    crypto.js      all client-side cryptography (SPEC.md §2/§3)
    http.js        axios instance, bearer auth, 401 → refresh-and-retry
    session.js     auth/session service: register/login/unlock/logout,
                    holds the in-memory "vault" (kek/UMK/privkey) — never persisted
    apps.js        apps/data/sharing service: combines api/* + crypto.js so
                    every consumer works with plaintext, never a raw DEK
    api/           one file per backend resource (auth, users, apps, data,
                    shares) — thin wire wrappers, no crypto, no state
  apps/
    registry.js    the plug-in point, see below
    demo/          example app: metadata + timestamped numeric readings
  views/           auth screens, app list (+ pending shares), app detail
                    (+ sharing panel)
  router/          vue-router, guards on session status
```

`lib/` has no Vue-specific dependency other than session.js using `reactive`
for its store — the crypto/http/api layers are plain JS and could be lifted
into any other frontend talking to the same backend.

## Adding a new app

1. Build a component under `src/apps/<slug>/` using `lib/apps.js` for all
   data access (never call `lib/api/*` or `lib/crypto.js` directly from an
   app component).
2. Register it in `src/apps/registry.js`:
   ```js
   import MyApp from './my-app/MyApp.vue'
   myApp: {
     slug: 'my-app',
     displayName: 'My App',
     color: '#2563eb',
     icon: '🗂️',
     component: MyApp,
     defaultMetadata: () => ({ name: 'New my-app' }),
   }
   ```
3. Done — it shows up in the "+ New app" picker and app list automatically.

Every app component receives `appId`, `metadata`, `dek`, and `role` as
props, and emits `metadata-updated` when it changes the metadata. `slug`
identifies the app *type* (which component loads); `appId` identifies the
*instance* — the same slug can back many independent app instances, so
components must always scope data access by `appId`, never by `slug` alone.

## Known spec deviations (and why)

- **AAD for `wrapped_umk`/`wrapped_privkey`** is bound to `username` instead
  of `user_id` (SPEC.md §2.1 says `user_id`). The server assigns `user_id`
  only once `/auth/register` returns, so the client cannot know it in
  advance to bind it into ciphertext created *for* that request. Username is
  the only stable identifier available beforehand.
- **DEK rotation's member list** is sourced from a small `_directory` map
  kept inside the (encrypted) app metadata, mapping `user_id → {username,
  publicKeyB64}`. The backend has no "get user by id" endpoint and
  `GET /apps/:id/shares` returns bare `user_id`s, so without this directory
  a rotation couldn't re-seal the new DEK to existing members.
