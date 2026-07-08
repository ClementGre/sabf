<script setup>
// Shown after a page reload when tokens are still valid but the in-memory
// vault (kek/UMK/privkey) was cleared. Re-derives keys from the passphrase
// locally, no network round trip (see lib/session.js unlock()).
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import * as session from '../lib/session.js'

const router = useRouter()
const passphrase = ref('')
const loading = ref(false)
const error = ref('')

async function submit() {
  loading.value = true
  error.value = ''
  try {
    await session.unlock(passphrase.value)
    router.push('/apps')
  } catch {
    error.value = 'Wrong passphrase'
  } finally {
    loading.value = false
  }
}

async function signOutInstead() {
  await session.logout()
  router.push('/login')
}
</script>

<template>
  <div class="mx-auto max-w-sm space-y-4 p-4 pt-12 sm:pt-24">
    <h1 class="text-xl font-semibold">Unlock</h1>
    <p class="text-sm text-neutral-600">
      Signed in as <strong>{{ session.sessionState.user?.username }}</strong>. Enter your passphrase to decrypt
      your data again.
    </p>
    <form class="card space-y-3" @submit.prevent="submit">
      <label class="block">
        <span class="field-label">Passphrase</span>
        <input v-model="passphrase" type="password" autocomplete="current-password" required autofocus />
      </label>
      <p v-if="error" class="text-sm text-red-600">{{ error }}</p>
      <button type="submit" class="btn-primary w-full" :disabled="loading">
        {{ loading ? 'Unlocking…' : 'Unlock' }}
      </button>
    </form>
    <button class="text-sm text-neutral-500 underline" @click="signOutInstead">Sign out instead</button>
  </div>
</template>
