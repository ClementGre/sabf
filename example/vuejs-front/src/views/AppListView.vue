<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import * as apps from '../lib/apps.js'
import { listAppDefinitions, getAppDefinition } from '../apps/registry.js'

const router = useRouter()
const myApps = ref([])
const pending = ref([])
const loading = ref(true)
const error = ref('')
const busyAppId = ref(null)
const showCreate = ref(false)

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const [active, pendingRows] = await Promise.all([apps.listApps(), apps.listPendingShares()])
    myApps.value = active.filter((a) => a.status === 'active')
    pending.value = pendingRows
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    loading.value = false
  }
}

onMounted(loadAll)

function def(slug) {
  return getAppDefinition(slug) || { displayName: slug, color: '#666', icon: '📦' }
}

// Each app instance gets a stable numeric index among instances of the same
// slug, so it can live at /<slug> (index 0) or /<slug>/<index> — see
// lib/apps.js sortBySlugOrder/slugPath.
const myAppsWithPath = computed(() => {
  const bySlug = {}
  for (const app of myApps.value) (bySlug[app.slug] ||= []).push(app)
  for (const slug in bySlug) bySlug[slug] = apps.sortBySlugOrder(bySlug[slug])

  return myApps.value.map((app) => {
    const index = bySlug[app.slug].findIndex((a) => a.appId === app.appId)
    return { ...app, path: apps.slugPath(app.slug, index) }
  })
})

function openApp(path) {
  router.push(path)
}

function manageApp(appId) {
  router.push(`/manage/${appId}`)
}

async function accept(appId) {
  busyAppId.value = appId
  try {
    await apps.acceptShare(appId)
    await loadAll()
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    busyAppId.value = null
  }
}

async function decline(appId) {
  busyAppId.value = appId
  try {
    await apps.declineShare(appId)
    await loadAll()
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    busyAppId.value = null
  }
}

const creating = ref(false)
async function createApp(slug) {
  creating.value = true
  error.value = ''
  try {
    const definition = getAppDefinition(slug)
    const created = await apps.createApp(slug, definition.defaultMetadata())
    const index = await apps.getSlugIndexForApp(created.appId, slug)
    showCreate.value = false
    router.push(apps.slugPath(slug, index))
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    creating.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-2xl space-y-6 p-4 pb-24">
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">Your apps</h1>
      <router-link to="/account" class="text-sm text-neutral-500 underline">Account</router-link>
    </div>

    <p v-if="error" class="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{{ error }}</p>

    <section v-if="pending.length" class="space-y-2">
      <h2 class="text-sm font-semibold text-neutral-600">Pending shares</h2>
      <div v-for="row in pending" :key="row.app_id" class="card flex items-center justify-between gap-2">
        <div class="flex items-center gap-2">
          <span class="text-xl">{{ def(row.slug).icon }}</span>
          <div>
            <div class="font-medium">{{ def(row.slug).displayName }}</div>
            <div class="text-xs text-neutral-500">shared with you · {{ row.role }}</div>
          </div>
        </div>
        <div class="flex gap-2">
          <button class="btn-secondary text-sm" :disabled="busyAppId === row.app_id" @click="decline(row.app_id)">
            Decline
          </button>
          <button class="btn-primary text-sm" :disabled="busyAppId === row.app_id" @click="accept(row.app_id)">
            Accept
          </button>
        </div>
      </div>
    </section>

    <section class="space-y-2">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold text-neutral-600">Apps</h2>
        <button class="btn-primary text-sm" @click="showCreate = !showCreate">+ New app</button>
      </div>

      <div v-if="showCreate" class="card space-y-2">
        <p class="text-sm text-neutral-600">Choose an app to create:</p>
        <div class="flex flex-wrap gap-2">
          <button
            v-for="d in listAppDefinitions()"
            :key="d.slug"
            class="btn-secondary text-sm"
            :disabled="creating"
            @click="createApp(d.slug)"
          >
            {{ d.icon }} {{ d.displayName }}
          </button>
        </div>
      </div>

      <p v-if="loading" class="text-sm text-neutral-500">Loading…</p>
      <p v-else-if="!myApps.length" class="text-sm text-neutral-500">No apps yet.</p>
      <div
        v-for="app in myAppsWithPath"
        :key="app.appId"
        class="card flex items-center gap-3"
        :style="{ borderLeft: `4px solid ${def(app.slug).color}` }"
      >
        <button class="flex flex-1 items-center gap-3 text-left" @click="openApp(app.path)">
          <span class="text-2xl">{{ def(app.slug).icon }}</span>
          <div class="flex-1">
            <div class="font-medium">{{ app.metadata?.name || def(app.slug).displayName }}</div>
            <div class="text-xs text-neutral-500">
              {{ def(app.slug).displayName }} · {{ app.role }}
            </div>
          </div>
        </button>
        <button class="btn-secondary shrink-0 text-sm" title="Sharing & delete" @click="manageApp(app.appId)">
          Manage
        </button>
      </div>
    </section>
  </div>
</template>
