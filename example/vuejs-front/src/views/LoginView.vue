<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import * as session from '../lib/session.js'

const router = useRouter()
const username = ref('')
const passphrase = ref('')
const loading = ref(false)
const error = ref('')

async function submit() {
  loading.value = true
  error.value = ''
  try {
    await session.login(username.value, passphrase.value)
    router.push('/apps')
  } catch (e) {
    error.value = e.response?.status === 401 ? 'Wrong username or passphrase' : e.response?.data?.error || e.message
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-sm space-y-4 p-4 pt-12 sm:pt-24">
    <h1 class="text-xl font-semibold">Sign in</h1>
    <form class="card space-y-3" @submit.prevent="submit">
      <label class="block">
        <span class="field-label">Username</span>
        <input v-model="username" type="text" autocomplete="username" required />
      </label>
      <label class="block">
        <span class="field-label">Passphrase</span>
        <input v-model="passphrase" type="password" autocomplete="current-password" required />
      </label>
      <p v-if="error" class="text-sm text-red-600">{{ error }}</p>
      <button type="submit" class="btn-primary w-full" :disabled="loading">
        {{ loading ? 'Signing in…' : 'Sign in' }}
      </button>
    </form>
    <p class="text-center text-sm text-neutral-600">
      No account? <router-link to="/register" class="underline">Register</router-link>
    </p>
    <p class="text-center text-xs text-neutral-400">
      There is no password recovery. Losing your passphrase means permanent loss of access to your data.
    </p>
  </div>
</template>
