// Thin axios wrapper. This file knows nothing about crypto or app state —
// it only attaches bearer tokens and retries once on 401 via a callback the
// session layer configures. Kept separate so the whole lib/ directory can be
// reused by any frontend talking to a SABF backend.
import axios from 'axios'

// window.__ENV__ (see public/env.js) is populated at container startup, taking
// precedence over import.meta.env which is baked in at build time.
function readEnv(key) {
    return window.__ENV__?.[key] || import.meta.env[key]
}

export const http = axios.create({
  baseURL: readEnv('VITE_API_BASE_URL') || 'http://localhost:8080',
})

let getAccessToken = () => null
let onUnauthorized = async () => null

export function configureHttp({ getAccessToken: g, onUnauthorized: o }) {
  getAccessToken = g
  onUnauthorized = o
}

http.interceptors.request.use((config) => {
  const token = getAccessToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

http.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && original && !original._retried) {
      original._retried = true
      const newToken = await onUnauthorized()
      if (newToken) {
        original.headers.Authorization = `Bearer ${newToken}`
        return http(original)
      }
    }
    return Promise.reject(error)
  },
)
