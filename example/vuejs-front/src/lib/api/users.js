// SPEC.md §5 "Users".
import { http } from '../http.js'

export function me() {
  return http.get('/users/me').then((r) => r.data)
}

// Unauthenticated lookup, used pre-login and to resolve a share recipient.
export function getByUsername(username) {
  return http.get(`/users/${encodeURIComponent(username)}`).then((r) => r.data)
}

export function deleteMe({ currentAuthKeyB64 }) {
  return http.delete('/users/me', { data: { current_auth_key: currentAuthKeyB64 } }).then((r) => r.data)
}
