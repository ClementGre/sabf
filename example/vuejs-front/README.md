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

## Storing & reading data

Everything a component needs to persist data lives in `lib/apps.js`
(imported as `import * as apps from '../../lib/apps.js'`). It wraps the raw
endpoints and `crypto.js`, so you always pass and receive **plaintext** JS
objects — the DEK never leaves this layer's calls, and the backend only ever
sees ciphertext. Never call `lib/api/*` or `lib/crypto.js` directly from an
app component.

There are two places to put data:

- **Metadata** — one small shared JSON object per app instance (its name,
  settings, a few flags). Encrypted as a single `apps.encrypted_metadata`
  blob. Read it from the `metadata` prop; write it with `updateMetadata`.
- **Data entries** — an unbounded list of records (`apps_data` rows), each a
  JSON object tagged with a plaintext `type` string. Use these for
  everything that grows: notes, readings, tasks, log lines, etc.

Both are encrypted under the same per-app `dek` prop before upload.

### Metadata

```js
// props.metadata is already-decrypted plaintext — read it directly.
const updated = { ...props.metadata, name: 'Renamed' }
await apps.updateMetadata(props.appId, props.dek, updated)
emit('metadata-updated', updated) // keep the parent's copy in sync
```

`updateMetadata` is last-write-wins. Metadata is a *shared* value (every
active member edits the same blob), so read-modify-write from the current
`metadata` prop rather than reconstructing it from scratch.

### Data entries

```js
// Create — `type` is a plaintext, immutable, queryable tag; `json` is any
// serializable object. Returns the new entry with a client-generated id.
const entry = await apps.createDataEntry(props.appId, props.dek, 'reading', {
  value: 42,
  label: 'optional',
})
// entry === { id, type, json, createdAt, editedAt }

// List — filter/paginate on the plaintext columns only (type + timestamps).
// Never on encrypted contents. Returns decrypted entries.
const { entries, nextCursor } = await apps.listDataEntries(props.appId, props.dek, {
  type: 'reading',      // optional
  limit: 200,           // defaults to 50 server-side, capped at 500
  cursor: undefined,    // pass a prior nextCursor to fetch the next page
  // also: created_from, created_to, edited_from, edited_to (RFC 3339)
})
// entries: [{ id, type, json, createdAt, editedAt }], newest-first is NOT
// guaranteed — sort client-side if you care about order.

// Update — pass the existing entry (its id + type) and the new json.
// `type` is immutable; only the json changes. Bumps editedAt.
await apps.updateDataEntry(props.appId, props.dek, entry, { ...entry.json, value: 43 })

// Delete
await apps.deleteDataEntry(props.appId, entry.id)
```

`type` is chosen by you and is part of the ciphertext's AAD, so it cannot be
changed after creation — pick it deliberately. `id` is a client-generated
UUIDv7 (time-ordered), so lexicographic id order is also creation order if
you need a stable sort. Filtering can only touch the plaintext columns
(`type`, `created_*`, `edited_*`); anything inside `json` is opaque to the
server, so query-by-content must happen after decrypt, client-side.

See `src/apps/demo/DemoApp.vue` for a complete, minimal example using all of
the above.

### App-instance lifecycle (used by the app list, not by components)

These also live in `lib/apps.js` and are how instances get created,
enumerated, and removed — the views call them; individual app components
usually don't:

- `listApps(slug?)` → active + pending instances (pending ones have
  `metadata: null, dek: null`).
- `getApp(appId)` / `getAppBySlugIndex(slug, index)` → one instance,
  decrypted.
- `createApp(slug, metadata)` → new owned instance (generates the appId +
  DEK).
- `deleteApp(appId)` (owner) / `leaveApp(appId)` (non-owner member).
- Sharing & rotation: `shareApp`, `listShares`, `listPendingShares`,
  `acceptShare`, `declineShare`, `removeShare`, `rotateDek` (see SPEC.md §3).

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
