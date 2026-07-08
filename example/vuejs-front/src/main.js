import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import { router } from './router/index.js'
import * as session from './lib/session.js'

session.init().finally(() => {
  createApp(App).use(router).mount('#app')
})
