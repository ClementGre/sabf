<script setup>
// Example app: edits its own metadata (name) and appends/lists timestamped
// numeric time-series entries stored as apps_data rows of type "reading".
// Everything here goes through lib/apps.js — no direct crypto or axios use.
import { ref, reactive, onMounted } from 'vue'
import * as apps from '../../lib/apps.js'
import AppTopBar from '../AppTopBar.vue'

const props = defineProps({
  appId: { type: String, required: true },
  metadata: { type: Object, required: true },
  dek: { type: Object, required: true }, // Uint8Array
  role: { type: String, required: true },
  // Provided by AppRunView from the registry — using AppTopBar is entirely
  // optional, these are only needed if an app chooses to render one.
  icon: { type: String, default: '' },
  color: { type: String, default: '#666' },
  displayName: { type: String, default: '' },
})
const emit = defineEmits(['metadata-updated'])

const nameDraft = ref(props.metadata.name || '')
const savingName = ref(false)

const entries = ref([])
const loadingEntries = ref(true)
const newValue = ref('')
const newLabel = ref('')
const newTime = ref(toLocalInput(new Date()))
const submitting = ref(false)
const error = ref('')

// id -> datetime-local draft while a row's timestamp is being edited
const timeDrafts = reactive({})

// <input type="datetime-local"> works in local time with no zone suffix, so
// convert to/from that shape at the edges; the API carries RFC 3339 (ISO).
function toLocalInput(d) {
  const dt = new Date(d)
  const pad = (n) => String(n).padStart(2, '0')
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}`
}

async function loadEntries() {
  loadingEntries.value = true
  error.value = ''
  try {
    const { entries: rows } = await apps.listDataEntries(props.appId, props.dek, {
      type: 'reading',
      limit: 200,
    })
    entries.value = rows.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    loadingEntries.value = false
  }
}

onMounted(loadEntries)

async function saveName() {
  savingName.value = true
  error.value = ''
  try {
    const updated = { ...props.metadata, name: nameDraft.value }
    await apps.updateMetadata(props.appId, props.dek, updated)
    emit('metadata-updated', updated)
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    savingName.value = false
  }
}

async function addReading() {
  const value = Number(newValue.value)
  if (Number.isNaN(value)) {
    error.value = 'value must be a number'
    return
  }
  submitting.value = true
  error.value = ''
  try {
    // created_at is client-controlled — send the chosen time (SPEC.md §5).
    const entry = await apps.createDataEntry(
      props.appId,
      props.dek,
      'reading',
      { value, label: newLabel.value || null },
      { createdAt: new Date(newTime.value).toISOString() },
    )
    entries.value.unshift(entry)
    resort()
    newValue.value = ''
    newLabel.value = ''
    newTime.value = toLocalInput(new Date())
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    submitting.value = false
  }
}

function resort() {
  entries.value.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
}

function startEditTime(entry) {
  timeDrafts[entry.id] = toLocalInput(entry.createdAt)
}

function cancelEditTime(entry) {
  delete timeDrafts[entry.id]
}

async function saveTime(entry) {
  error.value = ''
  try {
    // Re-uses the same json; only created_at moves. updateDataEntry echoes the
    // stored timestamps back so we keep the local row in sync.
    const updated = await apps.updateDataEntry(props.appId, props.dek, entry, entry.json, {
      createdAt: new Date(timeDrafts[entry.id]).toISOString(),
    })
    entry.createdAt = updated.createdAt
    entry.editedAt = updated.editedAt
    delete timeDrafts[entry.id]
    resort()
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  }
}

const rowState = reactive({}) // id -> { deleting }

async function removeReading(entry) {
  rowState[entry.id] = { deleting: true }
  try {
    await apps.deleteDataEntry(props.appId, entry.id)
    entries.value = entries.value.filter((e) => e.id !== entry.id)
  } catch (e) {
    error.value = e.response?.data?.error || e.message
  } finally {
    delete rowState[entry.id]
  }
}

function formatTime(iso) {
  return new Date(iso).toLocaleString()
}
</script>

<template>
  <div class="bg-amber-50 min-h-screen">
    <AppTopBar :app-id="appId" :icon="icon" :color="color" :title="metadata.name || displayName" />

    <div class="mx-auto max-w-2xl space-y-4 p-4">
      <p v-if="error" class="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{{ error }}</p>

      <section class="card space-y-2">
        <h2 class="text-sm font-semibold text-neutral-600">Metadata</h2>
        <label class="block">
          <span class="field-label">Name</span>
          <input v-model="nameDraft" type="text" />
        </label>
        <button
          class="btn-primary"
          :disabled="savingName || role === 'pending'"
          @click="saveName"
        >
          {{ savingName ? 'Saving…' : 'Save name' }}
        </button>
      </section>

      <section class="card space-y-3">
        <h2 class="text-sm font-semibold text-neutral-600">Add reading</h2>
        <div class="flex flex-col gap-2 sm:flex-row">
          <input v-model="newValue" type="number" step="any" placeholder="Value" class="sm:w-32" />
          <input v-model="newLabel" type="text" placeholder="Label (optional)" />
          <button class="btn-primary shrink-0" :disabled="submitting || !newValue" @click="addReading">
            Add
          </button>
        </div>
        <label class="block">
          <span class="field-label">Timestamp (client-set — backdate freely)</span>
          <input v-model="newTime" type="datetime-local" />
        </label>
      </section>

      <section class="card">
        <h2 class="mb-2 text-sm font-semibold text-neutral-600">Readings</h2>
        <p v-if="loadingEntries" class="text-sm text-neutral-500">Loading…</p>
        <p v-else-if="!entries.length" class="text-sm text-neutral-500">No readings yet.</p>
        <ul v-else class="divide-y divide-neutral-100">
          <li v-for="entry in entries" :key="entry.id" class="py-2">
            <div class="flex items-center justify-between gap-2">
              <div>
                <div class="font-medium">{{ entry.json.value }}</div>
                <div class="text-xs text-neutral-500">
                  {{ entry.json.label ? entry.json.label + ' · ' : '' }}{{ formatTime(entry.createdAt) }}
                </div>
              </div>
              <div class="flex shrink-0 gap-2">
                <button
                  v-if="timeDrafts[entry.id] === undefined"
                  class="btn-secondary text-sm"
                  @click="startEditTime(entry)"
                >
                  Edit time
                </button>
                <button
                  class="btn-secondary text-sm"
                  :disabled="rowState[entry.id]?.deleting"
                  @click="removeReading(entry)"
                >
                  Delete
                </button>
              </div>
            </div>
            <div v-if="timeDrafts[entry.id] !== undefined" class="mt-2 flex items-center gap-2">
              <input v-model="timeDrafts[entry.id]" type="datetime-local" />
              <button class="btn-primary shrink-0 text-sm" @click="saveTime(entry)">Save</button>
              <button class="btn-secondary shrink-0 text-sm" @click="cancelEditTime(entry)">Cancel</button>
            </div>
          </li>
        </ul>
      </section>
    </div>
  </div>
</template>
