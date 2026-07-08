<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import * as session from '../lib/session.js'

const router = useRouter()

const currentPass = ref('')
const newPass = ref('')
const newPassConfirm = ref('')
const changing = ref(false)
const changeError = ref('')
const changeSuccess = ref(false)

async function changePassphrase() {
  changeError.value = ''
  changeSuccess.value = false
  if (newPass.value.length < 8) {
    changeError.value = 'New passphrase must be at least 8 characters'
    return
  }
  if (newPass.value !== newPassConfirm.value) {
    changeError.value = 'New passphrases do not match'
    return
  }
  changing.value = true
  try {
    await session.changePassphrase(currentPass.value, newPass.value)
    changeSuccess.value = true
    currentPass.value = ''
    newPass.value = ''
    newPassConfirm.value = ''
  } catch (e) {
    changeError.value = e.response?.status === 401 ? 'Current passphrase is wrong' : e.response?.data?.error || e.message
  } finally {
    changing.value = false
  }
}

const deletePass = ref('')
const deleting = ref(false)
const deleteError = ref('')
const confirmingDelete = ref(false)

async function deleteAccount() {
  deleteError.value = ''
  deleting.value = true
  try {
    await session.deleteAccount(deletePass.value)
    router.push('/login')
  } catch (e) {
    deleteError.value = e.response?.status === 401 ? 'Passphrase is wrong' : e.response?.data?.error || e.message
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-sm space-y-6 p-4 pb-24">
    <h1 class="text-xl font-semibold">Account</h1>

    <section class="card space-y-3">
      <h2 class="text-sm font-semibold text-neutral-600">Change passphrase</h2>
      <label class="block">
        <span class="field-label">Current passphrase</span>
        <input v-model="currentPass" type="password" autocomplete="current-password" />
      </label>
      <label class="block">
        <span class="field-label">New passphrase</span>
        <input v-model="newPass" type="password" autocomplete="new-password" minlength="8" />
      </label>
      <label class="block">
        <span class="field-label">Confirm new passphrase</span>
        <input v-model="newPassConfirm" type="password" autocomplete="new-password" minlength="8" />
      </label>
      <p v-if="changeError" class="text-sm text-red-600">{{ changeError }}</p>
      <p v-if="changeSuccess" class="text-sm text-green-700">Passphrase changed. Other sessions were signed out.</p>
      <button class="btn-primary w-full" :disabled="changing" @click="changePassphrase">
        {{ changing ? 'Changing…' : 'Change passphrase' }}
      </button>
    </section>

    <section class="card space-y-3 border-red-200">
      <h2 class="text-sm font-semibold text-red-700">Delete account</h2>
      <p class="text-sm text-neutral-600">
        This permanently deletes your account, every app you own (and all data/shares within it), and removes
        you from apps others shared with you. Apps you own that are shared with others are destroyed for
        everyone. This cannot be undone.
      </p>
      <template v-if="!confirmingDelete">
        <button class="btn-danger w-full" @click="confirmingDelete = true">Delete my account…</button>
      </template>
      <template v-else>
        <label class="block">
          <span class="field-label">Confirm your passphrase</span>
          <input v-model="deletePass" type="password" autocomplete="current-password" />
        </label>
        <p v-if="deleteError" class="text-sm text-red-600">{{ deleteError }}</p>
        <div class="flex gap-2">
          <button class="btn-secondary flex-1" @click="confirmingDelete = false">Cancel</button>
          <button class="btn-danger flex-1" :disabled="deleting" @click="deleteAccount">
            {{ deleting ? 'Deleting…' : 'Confirm delete' }}
          </button>
        </div>
      </template>
    </section>
  </div>
</template>
