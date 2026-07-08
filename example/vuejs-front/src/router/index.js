import { createRouter, createWebHistory } from 'vue-router'
import { sessionState } from '../lib/session.js'

// URL scheme:
//   /<slug>          the first ("0th") active app instance of that slug
//   /<slug>/<n>      the nth (1-based-looking, but n=0 === /<slug>) instance
//   /manage/<appId>  sharing/membership/delete for one specific app instance
// Static routes (login, apps, manage, ...) always win over the dynamic
// /:slug catch-all because Vue Router ranks static path segments above
// dynamic ones regardless of registration order.
const routes = [
  { path: '/login', name: 'login', component: () => import('../views/LoginView.vue'), meta: { guest: true } },
  { path: '/register', name: 'register', component: () => import('../views/RegisterView.vue'), meta: { guest: true } },
  { path: '/unlock', name: 'unlock', component: () => import('../views/UnlockView.vue'), meta: { requiresSession: true } },
  { path: '/apps', name: 'apps', component: () => import('../views/AppListView.vue'), meta: { requiresUnlocked: true } },
  { path: '/manage/:id', name: 'app-manage', component: () => import('../views/AppDetailView.vue'), meta: { requiresUnlocked: true } },
  { path: '/account', name: 'account', component: () => import('../views/AccountView.vue'), meta: { requiresUnlocked: true } },
  {
    path: '/:slug/:index(\\d+)?',
    name: 'app-run',
    component: () => import('../views/AppRunView.vue'),
    meta: { requiresUnlocked: true, fullscreen: true },
  },
  { path: '/', redirect: '/apps' },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  // /<slug>/0 and /<slug> resolve to the same app instance — redirect to
  // the canonical (indexless) form so links/history stay consistent.
  if (to.name === 'app-run' && to.params.index === '0') {
    return { path: `/${to.params.slug}`, query: to.query, hash: to.hash }
  }

  const status = sessionState.status // 'loading' | 'signed-out' | 'locked' | 'unlocked'
  if (status === 'loading') return true

  if (to.meta.guest && status !== 'signed-out') return '/apps'
  if (to.meta.requiresSession && status === 'signed-out') return '/login'
  if (to.meta.requiresUnlocked) {
    if (status === 'signed-out') return '/login'
    if (status === 'locked') return '/unlock'
  }
  return true
})
