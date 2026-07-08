// Raw wire calls for SPEC.md §5 "Auth". No crypto, no state — callers pass
// already-derived/base64 values and get back the raw JSON response.
import { http } from '../http.js'

export function register({ username, authKeyB64, kdfSaltB64, wrappedUmkB64, publicKeyB64, wrappedPrivkeyB64 }) {
  return http
    .post('/auth/register', {
      username,
      auth_key: authKeyB64,
      kdf_salt: kdfSaltB64,
      wrapped_umk: wrappedUmkB64,
      public_key: publicKeyB64,
      wrapped_privkey: wrappedPrivkeyB64,
    })
    .then((r) => r.data)
}

export function login({ username, authKeyB64 }) {
  return http.post('/auth/login', { username, auth_key: authKeyB64 }).then((r) => r.data)
}

export function refresh({ refreshToken }) {
  return http.post('/auth/refresh', { refresh_token: refreshToken }).then((r) => r.data)
}

export function logout({ refreshToken }) {
  return http.post('/auth/logout', { refresh_token: refreshToken }).then((r) => r.data)
}

export function changePassphrase({ currentAuthKeyB64, newAuthKeyB64, newKdfSaltB64, newWrappedUmkB64 }) {
  return http
    .post('/auth/change-passphrase', {
      current_auth_key: currentAuthKeyB64,
      new_auth_key: newAuthKeyB64,
      new_kdf_salt: newKdfSaltB64,
      new_wrapped_umk: newWrappedUmkB64,
    })
    .then((r) => r.data)
}
