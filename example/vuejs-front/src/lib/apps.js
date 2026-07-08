// Apps/data/sharing service (SPEC.md §3 "Per app" key hierarchy + §5 Apps /
// App data / Sharing). Combines the raw endpoint wrappers in lib/api/* with
// crypto.js so every consumer (views, individual apps) works with plaintext
// objects and never touches a DEK directly.
import * as appsApi from './api/apps.js'
import * as dataApi from './api/data.js'
import * as sharesApi from './api/shares.js'
import * as usersApi from './api/users.js'
import * as crypto from './crypto.js'
import { getVault, sessionState } from './session.js'

// Decrypt this user's copy of an app's DEK from its sealed box.
function unsealDek(wrappedDekB64) {
  const { publicKey, privateKey } = getVault()
  return crypto.openSealBox(publicKey, privateKey, crypto.b64decode(wrappedDekB64))
}

function decryptMetadata(appId, dek, encryptedMetadataB64) {
  return crypto.decryptJson(dek, crypto.b64decode(encryptedMetadataB64), crypto.AAD.appMetadata(appId))
}

// --- apps -------------------------------------------------------------

// Returns [{ appId, slug, role, status, lastEditAt, metadata, dek }] for
// active apps; pending apps have `metadata: null, dek: null` (server omits
// wrapped_dek for pending rows per SPEC.md §5).
export async function listApps(slug) {
  const rows = await appsApi.list(slug ? { slug } : {})
  return rows.map((row) => {
    if (row.status !== 'active') {
      return { appId: row.app_id, slug: row.slug, role: row.role, status: row.status, lastEditAt: row.last_edit_at, metadata: null, dek: null }
    }
    const dek = unsealDek(row.wrapped_dek)
    const metadata = decryptMetadata(row.app_id, dek, row.encrypted_metadata)
    return { appId: row.app_id, slug: row.slug, role: row.role, status: row.status, lastEditAt: row.last_edit_at, metadata, dek }
  })
}

export async function getApp(appId) {
  const row = await appsApi.get(appId)
  const dek = unsealDek(row.wrapped_dek)
  const metadata = decryptMetadata(appId, dek, row.encrypted_metadata)
  return { appId, slug: row.slug, role: row.role, status: row.status, metadata, dek }
}

// Deterministic ordering across every instance of a slug, used to give each
// one a stable numeric index for URLs (example.com/<slug>, .../<slug>/1,
// .../<slug>/2, ...) without a dedicated backend field. UUIDv7 embeds a
// creation timestamp in its leading bits, so lexicographic string order on
// `appId` is also creation order.
export function sortBySlugOrder(appsOfSameSlug) {
  return [...appsOfSameSlug].sort((a, b) => (a.appId < b.appId ? -1 : a.appId > b.appId ? 1 : 0))
}

// Resolves the nth (0-based) active app instance of a slug, matching the
// example.com/<slug>[/<index>] URL scheme (index 0 is the bare slug path).
export async function getAppBySlugIndex(slug, index = 0) {
  const matches = (await listApps(slug)).filter((a) => a.status === 'active')
  const ordered = sortBySlugOrder(matches)
  return ordered[index] || null
}

// Index of `appId` among active instances of its own slug — the inverse of
// getAppBySlugIndex, used to build a slug URL back from a bare appId.
export async function getSlugIndexForApp(appId, slug) {
  const matches = (await listApps(slug)).filter((a) => a.status === 'active')
  const ordered = sortBySlugOrder(matches)
  const index = ordered.findIndex((a) => a.appId === appId)
  return index === -1 ? 0 : index
}

export function slugPath(slug, index) {
  return index > 0 ? `/${slug}/${index}` : `/${slug}`
}

// The backend has no "get user by id" endpoint (GET /users/:username only),
// so a member's public key can't be looked up from a bare user_id returned
// by GET /apps/:id/shares. We keep a small directory of {userId: {username,
// publicKeyB64}} inside the (encrypted) app metadata itself, populated as
// people are added, so rotation (§3.1) can re-seal to everyone without an
// extra lookup endpoint.
function withSelfInDirectory(metadata) {
  const { id, username, publicKeyB64 } = sessionState.user
  return { ...metadata, _directory: { ...(metadata._directory || {}), [id]: { username, publicKeyB64 } } }
}

// Creates a brand new app instance of the given slug, owned by the caller.
export async function createApp(slug, metadata) {
  const { publicKey } = getVault()
  const appId = crypto.randomUuidV7()
  const dek = crypto.generateKey()
  const fullMetadata = withSelfInDirectory(metadata)
  const encryptedMetadata = crypto.encryptJson(dek, fullMetadata, crypto.AAD.appMetadata(appId))
  const wrappedDek = crypto.sealBox(publicKey, dek)

  await appsApi.create({
    appId,
    slug,
    encryptedMetadataB64: crypto.b64encode(encryptedMetadata),
    wrappedDekB64: crypto.b64encode(wrappedDek),
  })
  return { appId, slug, role: 'owner', status: 'active', metadata: fullMetadata, dek }
}

export async function updateMetadata(appId, dek, metadata) {
  const encryptedMetadata = crypto.encryptJson(dek, metadata, crypto.AAD.appMetadata(appId))
  await appsApi.patchMetadata(appId, { encryptedMetadataB64: crypto.b64encode(encryptedMetadata) })
}

export function deleteApp(appId) {
  return appsApi.remove(appId)
}

export function leaveApp(appId) {
  return appsApi.leave(appId)
}

// --- app data (time series / freeform records) -------------------------

export async function createDataEntry(appId, dek, type, json) {
  const dataId = crypto.randomUuidV7()
  const encryptedJson = crypto.encryptJson(dek, json, crypto.AAD.appData(appId, dataId, type))
  await dataApi.create(appId, { dataId, type, encryptedJsonB64: crypto.b64encode(encryptedJson) })
  return { id: dataId, type, json, createdAt: new Date().toISOString(), editedAt: new Date().toISOString() }
}

export async function listDataEntries(appId, dek, opts = {}) {
  const page = await dataApi.list(appId, opts)
  return {
    nextCursor: page.next_cursor,
    entries: page.data.map((row) => ({
      id: row.id,
      type: row.type,
      json: crypto.decryptJson(dek, crypto.b64decode(row.encrypted_json), crypto.AAD.appData(appId, row.id, row.type)),
      createdAt: row.created_at,
      editedAt: row.edited_at,
    })),
  }
}

export async function updateDataEntry(appId, dek, entry, newJson) {
  const encryptedJson = crypto.encryptJson(dek, newJson, crypto.AAD.appData(appId, entry.id, entry.type))
  await dataApi.patch(appId, entry.id, { encryptedJsonB64: crypto.b64encode(encryptedJson) })
}

export function deleteDataEntry(appId, dataId) {
  return dataApi.remove(appId, dataId)
}

// --- sharing (SPEC.md §3 "Sharing" + §3.1 rotation) ---------------------

// Shares `appId` with `recipientUsername` and records their public key in
// the metadata directory (see withSelfInDirectory) so a future rotation can
// re-seal to them. Returns the updated (already-persisted) metadata.
export async function shareApp(appId, dek, metadata, recipientUsername) {
  const recipient = await usersApi.getByUsername(recipientUsername)
  const wrappedDek = crypto.sealBox(crypto.b64decode(recipient.public_key), dek)

  const updatedMetadata = {
    ...metadata,
    _directory: {
      ...(metadata._directory || {}),
      [recipient.user_id]: { username: recipientUsername, publicKeyB64: recipient.public_key },
    },
  }
  await updateMetadata(appId, dek, updatedMetadata)
  await sharesApi.create(appId, { recipientUserId: recipient.user_id, wrappedDekB64: crypto.b64encode(wrappedDek) })
  return updatedMetadata
}

export function listShares(appId) {
  return sharesApi.listForApp(appId)
}

export async function listPendingShares() {
  const rows = await sharesApi.listPending()
  return rows
}

export async function acceptShare(appId) {
  const { wrapped_dek } = await sharesApi.accept(appId)
  // Confirms the row is decryptable before returning; surfaces a clear
  // error immediately rather than a confusing failure on first app open.
  unsealDek(wrapped_dek)
  return true
}

export function declineShare(appId) {
  return sharesApi.decline(appId)
}

export function removeShare(appId, userId) {
  return sharesApi.remove(appId, userId)
}

// True DEK rotation/revocation (SPEC.md §3.1): re-encrypts metadata + every
// data row under a fresh DEK and re-seals it to every currently-active
// member except `excludeUserId` (looked up via the metadata directory, see
// withSelfInDirectory). Caller must be the owner and must already hold every
// data row's *decrypted* json (fetch via listDataEntries first). Any pending
// share sealed to the old DEK is left dangling by the server-side rotation
// (SPEC.md §3.1 note) — callers should cancel/reissue those separately.
export async function rotateDek(appId, { metadata, entries, excludeUserId } = {}) {
  const directory = metadata._directory || {}
  const shares = await listShares(appId)
  const keepUserIds = shares
    .filter((s) => s.status === 'active' && s.user_id !== excludeUserId)
    .map((s) => s.user_id)

  const newDek = crypto.generateKey()
  const newEncryptedMetadata = crypto.encryptJson(newDek, metadata, crypto.AAD.appMetadata(appId))

  const data = entries.map((entry) => ({
    id: entry.id,
    new_encrypted_json: crypto.b64encode(
      crypto.encryptJson(newDek, entry.json, crypto.AAD.appData(appId, entry.id, entry.type)),
    ),
  }))

  const access = keepUserIds
    .filter((userId) => directory[userId])
    .map((userId) => ({
      user_id: userId,
      new_wrapped_dek: crypto.b64encode(crypto.sealBox(crypto.b64decode(directory[userId].publicKeyB64), newDek)),
    }))

  await appsApi.rotate(appId, { newEncryptedMetadataB64: crypto.b64encode(newEncryptedMetadata), data, access })
  return newDek
}
