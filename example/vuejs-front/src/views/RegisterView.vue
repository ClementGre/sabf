<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import * as session from '../lib/session.js'

const router = useRouter()
const username = ref('')
const passphrase = ref('')
const confirm = ref('')
const loading = ref(false)
const error = ref('')

async function submit() {
  error.value = ''
  if (passphrase.value.length < 8) {
    error.value = 'Passphrase must be at least 8 characters'
    return
  }
  if (passphrase.value !== confirm.value) {
    error.value = 'Passphrases do not match'
    return
  }
  loading.value = true
  try {
    await session.register(username.value, passphrase.value)
    await session.login(username.value, passphrase.value)
    router.push('/apps')
  } catch (e) {
    error.value = e.response?.status === 409 ? 'Username already taken' : e.response?.data?.error || e.message
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-sm space-y-4 p-4 pt-12 sm:pt-24">
    <h1 class="text-xl font-semibold">Create account</h1>
    <p class="rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-800">
      This app cannot recover a lost passphrase. There is no "forgot password" — write it down somewhere safe.
    </p>
    <form class="card space-y-3" @submit.prevent="submit">
      <label class="block">
        <span class="field-label">Username</span>
        <input v-model="username" type="text" autocomplete="username" required />
      </label>
      <label class="block">
        <span class="field-label">Passphrase</span>
        <input v-model="passphrase" type="password" autocomplete="new-password" required minlength="8" />
      </label>
      <label class="block">
        <span class="field-label">Confirm passphrase</span>
        <input v-model="confirm" type="password" autocomplete="new-password" required minlength="8" />
      </label>
      <p v-if="error" class="text-sm text-red-600">{{ error }}</p>
      <button type="submit" class="btn-primary w-full" :disabled="loading">
        {{ loading ? 'Creating…' : 'Create account' }}
      </button>
    </form>
    <p class="text-center text-sm text-neutral-600">
      Already have an account? <router-link to="/login" class="underline">Sign in</router-link>
    </p>
  </div>
</template>
