<script setup>
// Optional building block for apps: a small back/title/manage bar. Nothing
// in the framework forces an app to render this — AppRunView.vue mounts the
// app component with zero chrome of its own, so a truly full-screen app
// (a canvas, a game) can skip it entirely. Apps that want the familiar
// "← Apps · title · Manage" bar just import and place this in their own
// template (see apps/demo/DemoApp.vue).
defineProps({
  appId: { type: String, required: true },
  title: { type: String, default: '' },
  icon: { type: String, default: '' },
  color: { type: String, default: '#666' },
})
</script>

<template>
  <header
    class="sticky top-0 z-10 flex items-center justify-between border-b border-neutral-200 bg-white px-4 py-3"
    :style="{ borderBottomColor: color, borderBottomWidth: '3px' }"
  >
    <router-link to="/apps" class="text-sm text-neutral-500 underline">← Apps</router-link>
    <div class="flex items-center gap-2 font-medium">
      <span v-if="icon">{{ icon }}</span>
      <span>{{ title }}</span>
    </div>
    <router-link :to="`/manage/${appId}`" class="text-sm text-neutral-500 underline">Manage</router-link>
  </header>
</template>
