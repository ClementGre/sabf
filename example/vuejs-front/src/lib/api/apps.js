// SPEC.md §5 "Apps". Payload field names/shapes are passed through verbatim
// (already base64-encoded ciphertext) — the service layer does all
// encoding/decoding.
import { http } from '../http.js'

export function list({ slug } = {}) {
  return http.get('/apps', { params: slug ? { slug } : {} }).then((r) => r.data)
}

export function create({ appId, slug, encryptedMetadataB64, wrappedDekB64 }) {
  return http
    .post('/apps', {
      app_id: appId,
      slug,
      encrypted_metadata: encryptedMetadataB64,
      wrapped_dek: wrappedDekB64,
    })
    .then((r) => r.data)
}

export function get(appId) {
  return http.get(`/apps/${appId}`).then((r) => r.data)
}

export function patchMetadata(appId, { encryptedMetadataB64 }) {
  return http.patch(`/apps/${appId}`, { encrypted_metadata: encryptedMetadataB64 }).then((r) => r.data)
}

export function rotate(appId, { newEncryptedMetadataB64, data, access }) {
  return http
    .post(`/apps/${appId}/rotate`, {
      new_encrypted_metadata: newEncryptedMetadataB64,
      data,
      access,
    })
    .then((r) => r.data)
}

export function remove(appId) {
  return http.delete(`/apps/${appId}`).then((r) => r.data)
}

export function leave(appId) {
  return http.post(`/apps/${appId}/leave`).then((r) => r.data)
}
