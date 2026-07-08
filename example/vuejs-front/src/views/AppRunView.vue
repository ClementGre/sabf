<script setup>
// Full-screen host for a single app instance, at its own URL
// (example.com/<slug> or /<slug>/<index>) so the browser back button and
// reloads behave normally. This view renders *only* the app component —
// no forced header, no max-width wrapper. Sharing/delete/membership (things
// independent of the app itself) live at the separate /manage/:id route.
// A top bar is available as an *optional* component (../apps/AppTopBar.vue)
// that an app can include in its own template if it wants one — see
// apps/demo/DemoApp.vue for an example — but this view never adds one on
// the app's behalf.
import { ref, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import * as apps from '../lib/apps.js'
import { getAppDefinition } from '../apps/registry.js'

const route = useRoute()
const slug = computed(() => route.params.slug)
const index = computed(() => Number(route.params.index || 0))

const app = ref(null)
const loading = ref(true)
const error = ref('')

const definition = computed(() => getAppDefinition(slug.value))

async function load() {
  loading.value = true
  error.value = ''
  app.value = null
  try {
    const match = await apps.getAppBySlugIndex(slug.value, index.value)
    if (!match) {
      error.value = `No app found at /${slug.value}${index.value ? '/' + index.value : ''}`
      return
    }
    app.value = await apps.getApp(match.appId)
  } catch (e) {
    error.value = e.response?.status === 403 ? 'Access pending — accept the share first.' : e.response?.data?.error || e.message
  } finally {
    loading.value = false
  }
}

watch([slug, index], load, { immediate: true })

function onMetadataUpdated(metadata) {
  app.value.metadata = metadata
}
</script>

<template>
  <p v-if="error" class="p-4 text-sm text-red-700">{{ error }}</p>
  <p v-else-if="loading" class="p-4 text-sm text-neutral-500">Loading…</p>
  <p v-else-if="app && !definition" class="p-4 text-sm text-red-600">
    No app registered for slug "{{ app.slug }}".
  </p>
  <component
    :is="definition.component"
    v-else-if="app && definition"
    :app-id="app.appId"
    :slug="app.slug"
    :metadata="app.metadata"
    :dek="app.dek"
    :role="app.role"
    :icon="definition.icon"
    :color="definition.color"
    :display-name="definition.displayName"
    @metadata-updated="onMetadataUpdated"
  />
</template>
