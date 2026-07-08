// Session/auth service (SPEC.md §3 key hierarchy + §5 Auth/Users endpoints).
// Owns the one place in the app allowed to hold key material in memory:
// kek, UMK, and the X25519 keypair never touch localStorage. Only
// already-encrypted/wrapped values (which the server holds anyway) and the
// bearer tokens are persisted, so a page reload requires the passphrase
// again to "unlock" (re-derive kek, unwrap UMK/privkey) without a full
// server round trip.
import { reactive, readonly } from 'vue'
import * as authApi from './api/auth.js'
import * as usersApi from './api/users.js'
import { configureHttp } from './http.js'
import * as crypto from './crypto.js'

const STORAGE_KEY = 'sabf.session.v1'

const state = reactive({
  status: 'loading', // 'loading' | 'signed-out' | 'locked' | 'unlocked'
  user: null, // { id, username, publicKeyB64 }
})

// In-memory only — never persisted.
let vault = null // { kek, umk, privateKey, publicKey }
let tokens = { accessToken: null, refreshToken: null }
let persisted = null // last-known localStorage payload (ciphertext + tokens)
let refreshInFlight = null

function loadPersisted() {
  const raw = localStorage.getItem(STORAGE_KEY)
  return raw ? JSON.parse(raw) : null
}

function savePersisted(p) {
  persisted = p
  if (p) localStorage.setItem(STORAGE_KEY, JSON.stringify(p))
  else localStorage.removeItem(STORAGE_KEY)
}

configureHttp({
  getAccessToken: () => tokens.accessToken,
  onUnauthorized: async () => {
    if (!tokens.refreshToken) return null
    if (!refreshInFlight) refreshInFlight = doRefresh().finally(() => (refreshInFlight = null))
    return refreshInFlight
  },
})

async function doRefresh() {
  try {
    const res = await authApi.refresh({ refreshToken: tokens.refreshToken })
    tokens = { accessToken: res.access_token, refreshToken: res.refresh_token }
    if (persisted) savePersisted({ ...persisted, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken })
    return tokens.accessToken
  } catch {
    signOutLocal()
    return null
  }
}

function signOutLocal() {
  vault = null
  tokens = { accessToken: null, refreshToken: null }
  savePersisted(null)
  state.status = 'signed-out'
  state.user = null
}

export async function init() {
  await crypto.ready()
  const p = loadPersisted()
  if (!p) {
    state.status = 'signed-out'
    return
  }
  persisted = p
  tokens = { accessToken: p.accessToken, refreshToken: p.refreshToken }
  state.user = { id: p.userId, username: p.username, publicKeyB64: p.publicKey }
  state.status = 'locked'
}

export async function register(username, passphrase) {
  await crypto.ready()
  const kdfSalt = crypto.generateSalt()
  const kdfParams = { algorithm: 'argon2id', mem_cost_kib: 19456, time_cost: 2, parallelism: 1 }
  const { authKey, kek } = await crypto.derivePassphraseKeys(passphrase, crypto.b64encode(kdfSalt), kdfParams)

  const umk = crypto.generateKey()
  const keyPair = crypto.generateKeyPair()

  // SPEC.md §2.1 binds wrapped_umk/wrapped_privkey AAD to user_id, but the
  // server assigns user_id (UUIDv7) only once /auth/register completes, so
  // the client cannot know it beforehand. We bind on username instead — the
  // only stable identifier known before registration — which still prevents
  // cross-user ciphertext splicing, just keyed on a different stable field.
  const wrappedUmk = crypto.encryptWithKey(kek, umk, crypto.AAD.umk(username))
  const wrappedPrivkey = crypto.encryptWithKey(umk, keyPair.privateKey, crypto.AAD.privkey(username))

  const res = await authApi.register({
    username,
    authKeyB64: crypto.b64encode(authKey),
    kdfSaltB64: crypto.b64encode(kdfSalt),
    wrappedUmkB64: crypto.b64encode(wrappedUmk),
    publicKeyB64: crypto.b64encode(keyPair.publicKey),
    wrappedPrivkeyB64: crypto.b64encode(wrappedPrivkey),
  })
  return res
}

export async function login(username, passphrase) {
  await crypto.ready()
  const userLookup = await usersApi.getByUsername(username)
  const { authKey, kek } = await crypto.derivePassphraseKeys(passphrase, userLookup.kdf_salt, userLookup.kdf_params)

  const res = await authApi.login({ username, authKeyB64: crypto.b64encode(authKey) })

  const umk = crypto.decryptWithKey(kek, crypto.b64decode(res.wrapped_umk), crypto.AAD.umk(username))
  const privateKey = crypto.decryptWithKey(umk, crypto.b64decode(res.wrapped_privkey), crypto.AAD.privkey(username))
  const publicKey = crypto.b64decode(res.public_key)

  vault = { kek, umk, privateKey, publicKey }
  tokens = { accessToken: res.access_token, refreshToken: res.refresh_token }

  const me = await usersApi.me()
  state.user = { id: me.user_id, username: me.username, publicKeyB64: res.public_key }
  state.status = 'unlocked'

  savePersisted({
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    userId: me.user_id,
    username: me.username,
    publicKey: res.public_key,
    kdfSalt: res.kdf_salt,
    kdfParams: res.kdf_params,
    wrappedUmk: res.wrapped_umk,
    wrappedPrivkey: res.wrapped_privkey,
  })
}

// Re-derive kek/UMK/privkey from the passphrase using cached ciphertext
// (no network round trip) after a page reload.
export async function unlock(passphrase) {
  if (!persisted) throw new Error('no session to unlock')
  await crypto.ready()
  const { authKey: _authKey, kek } = await crypto.derivePassphraseKeys(passphrase, persisted.kdfSalt, persisted.kdfParams)
  const umk = crypto.decryptWithKey(kek, crypto.b64decode(persisted.wrappedUmk), crypto.AAD.umk(persisted.username))
  const privateKey = crypto.decryptWithKey(umk, crypto.b64decode(persisted.wrappedPrivkey), crypto.AAD.privkey(persisted.username))
  const publicKey = crypto.b64decode(persisted.publicKey)
  vault = { kek, umk, privateKey, publicKey }
  state.status = 'unlocked'
}

export async function logout() {
  try {
    if (tokens.refreshToken) await authApi.logout({ refreshToken: tokens.refreshToken })
  } catch {
    // best-effort; fall through to local sign-out regardless
  }
  signOutLocal()
}

export async function changePassphrase(currentPassphrase, newPassphrase) {
  if (!vault || !state.user) throw new Error('not unlocked')
  await crypto.ready()
  const current = await crypto.derivePassphraseKeys(currentPassphrase, persisted.kdfSalt, persisted.kdfParams)
  const newKdfSalt = crypto.generateSalt()
  const newParams = persisted.kdfParams
  const next = await crypto.derivePassphraseKeys(newPassphrase, crypto.b64encode(newKdfSalt), newParams)

  const newWrappedUmk = crypto.encryptWithKey(next.kek, vault.umk, crypto.AAD.umk(state.user.username))

  await authApi.changePassphrase({
    currentAuthKeyB64: crypto.b64encode(current.authKey),
    newAuthKeyB64: crypto.b64encode(next.authKey),
    newKdfSaltB64: crypto.b64encode(newKdfSalt),
    newWrappedUmkB64: crypto.b64encode(newWrappedUmk),
  })

  vault.kek = next.kek
  savePersisted({
    ...persisted,
    kdfSalt: crypto.b64encode(newKdfSalt),
    wrappedUmk: crypto.b64encode(newWrappedUmk),
  })
  // Passphrase change revokes all OTHER sessions server-side; this session
  // stays valid since its access/refresh tokens are unaffected.
}

export async function deleteAccount(currentPassphrase) {
  if (!persisted) throw new Error('not signed in')
  await crypto.ready()
  const { authKey } = await crypto.derivePassphraseKeys(currentPassphrase, persisted.kdfSalt, persisted.kdfParams)
  await usersApi.deleteMe({ currentAuthKeyB64: crypto.b64encode(authKey) })
  signOutLocal()
}

export function getVault() {
  if (!vault) throw new Error('vault is locked — call unlock() first')
  return vault
}

export function isUnlocked() {
  return state.status === 'unlocked'
}

export const sessionState = readonly(state)
