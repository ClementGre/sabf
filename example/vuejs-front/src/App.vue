<script setup>
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { sessionState } from './lib/session.js'
import * as session from './lib/session.js'

const router = useRouter()
const route = useRoute()
// App components render full-screen with their own back navigation, at
// their own URL (so the browser back button works) — no shared chrome.
const showNav = computed(() => sessionState.status === 'unlocked' && !route.meta.fullscreen)

async function signOut() {
  await session.logout()
  router.push('/login')
}
</script>

<template>
  <div class="flex min-h-full flex-col">
    <header v-if="showNav" class="sticky top-0 z-10 flex items-center justify-between border-b border-neutral-200 bg-white px-4 py-3">
      <router-link to="/apps" class="font-semibold">SABF Apps</router-link>
      <div class="flex items-center gap-3 text-sm">
        <span class="text-neutral-500">{{ sessionState.user?.username }}</span>
        <button class="btn-secondary py-1 text-sm" @click="signOut">Sign out</button>
      </div>
    </header>
    <main class="flex-1 grow">
      <router-view />
    </main>
  </div>
</template>
