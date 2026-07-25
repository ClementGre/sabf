// SPEC.md §5 "App data".
import { http } from '../http.js'

export function create(appId, { dataId, type, encryptedJsonB64, createdAt }) {
  return http
    .post(`/apps/${appId}/data`, { data_id: dataId, type, encrypted_json: encryptedJsonB64, created_at: createdAt })
    .then((r) => r.data)
}

export function list(appId, { type, createdFrom, createdTo, editedFrom, editedTo, limit, cursor } = {}) {
  return http
    .get(`/apps/${appId}/data`, {
      params: {
        type,
        created_from: createdFrom,
        created_to: createdTo,
        edited_from: editedFrom,
        edited_to: editedTo,
        limit,
        cursor,
      },
    })
    .then((r) => r.data)
}

export function patch(appId, dataId, { encryptedJsonB64, createdAt }) {
  // `created_at` is optional — omitted (undefined) leaves the stored value.
  return http
    .patch(`/apps/${appId}/data/${dataId}`, { encrypted_json: encryptedJsonB64, created_at: createdAt })
    .then((r) => r.data)
}

export function remove(appId, dataId) {
  return http.delete(`/apps/${appId}/data/${dataId}`).then((r) => r.data)
}
