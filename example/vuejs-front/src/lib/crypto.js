// All content cryptography (SPEC.md §2/§3) lives here and only here. The
// server never sees any of these keys — it only stores/serves the outputs.
//
// Primitives (must match SPEC.md §2 exactly for interop with any other
// libsodium-based client):
//   - Argon2id (crypto_pwhash, ALG_ARGON2ID13) for passphrase stretching
//   - XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf) for symmetric
//     encryption, wire format `nonce(24B) || ciphertext || tag`
//   - X25519 sealed boxes (crypto_box_seal / crypto_box_seal_open) for
//     wrapping a DEK to a specific recipient
import sodium from 'libsodium-wrappers-sumo'

let readyPromise = null

export function ready() {
  if (!readyPromise) readyPromise = sodium.ready
  return readyPromise
}

// --- base64 (standard, padded — matches the server's `base64::STANDARD` /
// api::bytes::B64 wire format) ---------------------------------------------

export function b64encode(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL)
}

export function b64decode(str) {
  return sodium.from_base64(str, sodium.base64_variants.ORIGINAL)
}

// --- AAD ---------------------------------------------------------------
// AAD is authenticated but never stored (SPEC.md §2.1); it's recomputed at
// decrypt time from row identity. Any stable, unambiguous encoding works as
// long as every client agrees on it — UUIDs/types never contain ':'.

function aad(parts) {
  return new TextEncoder().encode(parts.join(':'))
}

export const AAD = {
  appMetadata: (appId) => aad([appId, 'metadata']),
  appData: (appId, dataId, type) => aad([appId, dataId, type]),
  umk: (userId) => aad([userId, 'umk']),
  privkey: (userId) => aad([userId, 'privkey']),
}

// --- KDF (client-side passphrase stretching, SPEC.md §3/§7) ---------------

// Hard floor: refuse to derive with params weaker than this, even if a
// (possibly malicious) server advertises less. Matches the framework's
// current fixed constants (src/crypto.rs) with headroom to raise them later
// without locking out this client.
const MIN_MEM_COST_KIB = 19_456
const MIN_TIME_COST = 2
const MAX_PARALLELISM = 1

function assertParamsSafe(params) {
  const memCostKib = params.mem_cost_kib
  const timeCost = params.time_cost
  const parallelism = params.parallelism
  if (params.algorithm !== 'argon2id') {
    throw new Error(`unsupported KDF algorithm: ${params.algorithm}`)
  }
  if (memCostKib < MIN_MEM_COST_KIB || timeCost < MIN_TIME_COST) {
    throw new Error('server-advertised KDF params are below the safe floor — refusing to derive')
  }
  if (parallelism !== MAX_PARALLELISM) {
    // libsodium's Argon2id only supports parallelism=1; the framework's
    // fixed params use 1 as well, but guard explicitly against drift.
    throw new Error(`unsupported KDF parallelism: ${parallelism}`)
  }
}

// Returns { authKey: Uint8Array(32), kek: Uint8Array(32) } — the first/second
// half of the 64-byte Argon2id output (SPEC.md §3).
export async function derivePassphraseKeys(passphrase, kdfSaltB64, kdfParams) {
  await ready()
  assertParamsSafe(kdfParams)
  const salt = b64decode(kdfSaltB64)
  const out = sodium.crypto_pwhash(
    64,
    passphrase,
    salt,
    kdfParams.time_cost,
    kdfParams.mem_cost_kib * 1024,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )
  return { authKey: out.slice(0, 32), kek: out.slice(32, 64) }
}

export function generateSalt() {
  return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
}

// --- symmetric encryption (XChaCha20-Poly1305) -----------------------------

export function generateKey() {
  return sodium.crypto_aead_xchacha20poly1305_ietf_keygen()
}

// Returns Uint8Array `nonce(24B) || ciphertext || tag`.
export function encryptWithKey(key, plaintextBytes, aadBytes) {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const combined = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
    aadBytes,
    null,
    nonce,
    key,
  )
  const out = new Uint8Array(nonce.length + combined.length)
  out.set(nonce, 0)
  out.set(combined, nonce.length)
  return out
}

export function decryptWithKey(key, blob, aadBytes) {
  const nonceLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  const nonce = blob.slice(0, nonceLen)
  const combined = blob.slice(nonceLen)
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, combined, aadBytes, nonce, key)
}

export function encryptJson(key, obj, aadBytes) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj))
  return encryptWithKey(key, bytes, aadBytes)
}

export function decryptJson(key, blob, aadBytes) {
  const bytes = decryptWithKey(key, blob, aadBytes)
  return JSON.parse(new TextDecoder().decode(bytes))
}

// --- asymmetric (X25519 keypair + sealed boxes) ----------------------------

export function generateKeyPair() {
  const kp = sodium.crypto_box_keypair()
  return { publicKey: kp.publicKey, privateKey: kp.privateKey }
}

export function sealBox(recipientPublicKey, messageBytes) {
  return sodium.crypto_box_seal(messageBytes, recipientPublicKey)
}

export function openSealBox(publicKey, privateKey, ciphertext) {
  return sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey)
}

export function randomUuidV7() {
  // Client generates all resource UUIDs (SPEC.md §1). UUIDv7: 48-bit ms
  // timestamp + version/variant bits + random tail, so ids stay time-ordered.
  const bytes = sodium.randombytes_buf(16)
  const ts = BigInt(Date.now())
  for (let i = 0; i < 6; i++) {
    bytes[i] = Number((ts >> BigInt(8 * (5 - i))) & 0xffn)
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
