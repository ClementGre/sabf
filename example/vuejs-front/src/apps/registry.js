// The plug-in point: to ship a new app, build its component (using the
// shared lib/apps.js + lib/crypto.js layer) under src/apps/<slug>/, then add
// one entry here. Nothing else in the framework UI needs to change.
//
// `slug` identifies the app TYPE (which component/UI loads the data) and is
// shared across every instance of that app. It is NOT the key that
// identifies one instance of data — a given slug can have many independent
// app instances (e.g. two separate "demo" apps), each with its own appId.
// Components always receive both `slug` and `appId` as props for this
// reason: `appId` is what actually scopes which data is loaded.
import DemoApp from './demo/DemoApp.vue'

export const appRegistry = {
  demo: {
    slug: 'demo',
    displayName: 'Demo',
    description: 'Edit metadata and record timestamped numeric readings.',
    color: '#edb43a',
    icon: '📈',
    component: DemoApp,
    defaultMetadata: () => ({ name: 'New demo app' }),
  },
}

export function getAppDefinition(slug) {
  return appRegistry[slug] || null
}

export function listAppDefinitions() {
  return Object.values(appRegistry)
}
