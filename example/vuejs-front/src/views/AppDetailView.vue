<script setup>
// Management page for a single app instance: everything independent of the
// app's own UI — sharing/membership (SPEC.md §5 Sharing), delete, leave.
// The app itself renders full-screen at its own URL (example.com/<slug> or
// /<slug>/<index>, AppRunView.vue) so the browser back button works and
// this page's chrome (header, sharing panel) never competes with the app's
// own UI.
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import * as apps from '../lib/apps.js'
import { getAppDefinition } from '../apps/registry.js'

const route = useRoute()
const router = useRouter()
const appId = computed(() => route.params.id)

const app = ref(null)
const loading = ref(true)
const error = ref('')
const openPath = ref(null)

const definition = computed(() => (app.value ? getAppDefinition(app.value.slug) : null))
const isOwner = computed(() => app.value?.role === 'owner')

async function load() {
  loading.value = true
  error.value = ''
  try {
    app.value = await apps.getApp(appId.value)
    const index = await apps.getSlugIndexForApp(appId.value, app.value.slug)
    openPath.value = apps.slugPath(app.value.slug, index)
  } catch (e) {
    error.value = e.response?.status === 403 ? 'Access pending — accept the share first.' : e.response?.data?.error || e.message
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await load()
  await loadShares()
})

// --- sharing panel state ---
const shares = ref([])
const loadingShares = ref(false)
const shareUsername = ref('')
const sharing = ref(false)
const shareError = ref('')

async function loadShares() {
  if (!isOwner.value) return
  loadingShares.value = true
  try {
    shares.value = await apps.listShares(appId.value)
  } catch (e) {
    shareError.value = e.response?.data?.error || e.message
  } finally {
    loadingShares.value = false
  }
}

async function submitShare() {
  sharing.value = true
  shareError.value = ''
  try {
    const updatedMetadata = await apps.shareApp(appId.value, app.value.dek, app.value.metadata, shareUsername.value)
    app.value.metadata = updatedMetadata
    shareUsername.value = ''
    await loadShares()
  } catch (e) {
    shareError.value = e.response?.status === 404 ? 'No such user' : e.response?.data?.error || e.message
  } finally {
    sharing.value = false
  }
}

const revokingUserId = ref(null)
async function revoke(userId) {
  // True revocation: rotate the DEK excluding this user, then drop their
  // membership row (SPEC.md §3.1 — this endpoint alone doesn't rotate).
  revokingUserId.value = userId
  shareError.value = ''
  try {
    const { entries } = await apps.listDataEntries(appId.value, app.value.dek, { limit: 500 })
    const newDek = await apps.rotateDek(appId.value, { metadata: app.value.metadata, entries, excludeUserId: userId })
    await apps.removeShare(appId.value, userId)
    app.value.dek = newDek
    await loadShares()
  } catch (e) {
    shareError.value = e.response?.data?.error || e.message
  } finally {
    revokingUserId.value = null
  }
}

const leaving = ref(false)
async function leave() {
  leaving.value = true
  try {
    await apps.leaveApp(appId.value)
    router.push('/apps')
  } catch (e) {
    error.value = e.response?.data?.error || e.message
    leaving.value = false
  }
}

const deleting = ref(false)
const confirmingDelete = ref(false)
async function remove() {
  deleting.value = true
  try {
    await apps.deleteApp(appId.value)
    router.push('/apps')
  } catch (e) {
    error.value = e.response?.data?.error || e.message
    deleting.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-2xl space-y-4 p-4 pb-24">
    <div class="flex items-center gap-2">
      <button class="text-sm text-neutral-500 underline" @click="router.push('/apps')">← Apps</button>
    </div>

    <p v-if="error" class="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{{ error }}</p>
    <p v-if="loading" class="text-sm text-neutral-500">Loading…</p>

    <template v-if="app && !loading">
      <div class="flex items-center justify-between gap-2" :style="{ borderBottom: `3px solid ${definition?.color || '#666'}` }">
        <h1 class="flex items-center gap-2 py-2 text-xl font-semibold">
          <span>{{ definition?.icon }}</span>
          <span>{{ app.metadata?.name || definition?.displayName || app.slug }}</span>
        </h1>
        <router-link v-if="openPath" :to="openPath" class="btn-primary text-sm">Open app →</router-link>
      </div>

      <section v-if="isOwner" class="card space-y-3">
        <h2 class="text-sm font-semibold text-neutral-600">Members</h2>
        <p v-if="loadingShares" class="text-sm text-neutral-500">Loading…</p>
        <ul v-else class="divide-y divide-neutral-100">
          <li v-for="s in shares" :key="s.user_id" class="flex items-center justify-between gap-2 py-2 text-sm">
            <div>
              <span class="font-medium">{{ app.metadata?._directory?.[s.user_id]?.username || s.user_id }}</span>
              <span class="ml-2 text-xs text-neutral-500">{{ s.role }} · {{ s.status }}</span>
            </div>
            <button
              v-if="s.role !== 'owner'"
              class="btn-danger text-xs"
              :disabled="revokingUserId === s.user_id"
              @click="revoke(s.user_id)"
            >
              {{ revokingUserId === s.user_id ? 'Revoking…' : 'Revoke' }}
            </button>
          </li>
        </ul>

        <form class="flex gap-2 pt-2" @submit.prevent="submitShare">
          <input v-model="shareUsername" type="text" placeholder="Username to share with" required />
          <button class="btn-primary shrink-0" :disabled="sharing">{{ sharing ? 'Sharing…' : 'Share' }}</button>
        </form>
        <p v-if="shareError" class="text-sm text-red-600">{{ shareError }}</p>
        <p class="text-xs text-neutral-400">
          Revoke rotates the encryption key in place and re-seals it to everyone else, so the removed member
          loses access to future changes (they may already have copied past plaintext).
        </p>
      </section>

      <section class="card space-y-2">
        <h2 class="text-sm font-semibold text-neutral-600">Danger zone</h2>
        <button v-if="!isOwner" class="btn-secondary w-full" :disabled="leaving" @click="leave">
          {{ leaving ? 'Leaving…' : 'Leave this app' }}
        </button>
        <template v-if="isOwner">
          <button v-if="!confirmingDelete" class="btn-danger w-full" @click="confirmingDelete = true">
            Delete this app…
          </button>
          <div v-else class="space-y-2">
            <p class="text-sm text-neutral-600">
              This deletes the app for every member, including anyone it's shared with. This cannot be undone.
            </p>
            <div class="flex gap-2">
              <button class="btn-secondary flex-1" @click="confirmingDelete = false">Cancel</button>
              <button class="btn-danger flex-1" :disabled="deleting" @click="remove">
                {{ deleting ? 'Deleting…' : 'Confirm delete' }}
              </button>
            </div>
          </div>
        </template>
      </section>
    </template>
  </div>
</template>
