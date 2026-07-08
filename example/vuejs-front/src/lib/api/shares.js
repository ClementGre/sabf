// SPEC.md §5 "Sharing" (owner-only issuance in v0.2).
import { http } from '../http.js'

export function create(appId, { recipientUserId, wrappedDekB64 }) {
  return http
    .post(`/apps/${appId}/shares`, { recipient_user_id: recipientUserId, wrapped_dek: wrappedDekB64 })
    .then((r) => r.data)
}

export function listForApp(appId) {
  return http.get(`/apps/${appId}/shares`).then((r) => r.data)
}

export function listPending() {
  return http.get('/shares/pending').then((r) => r.data)
}

export function accept(appId) {
  return http.post(`/apps/${appId}/shares/accept`).then((r) => r.data)
}

export function decline(appId) {
  return http.post(`/apps/${appId}/shares/decline`).then((r) => r.data)
}

export function remove(appId, userId) {
  return http.delete(`/apps/${appId}/shares/${userId}`).then((r) => r.data)
}
