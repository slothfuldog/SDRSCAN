import { defineNuxtModule } from '@nuxt/kit'

// Removes @nuxt/ui's runtime "colors" plugin (inline <style> + inline <script>); its CSS is shipped statically in
// assets/css/ui-colors.css instead, so the page runs under `style-src 'self'` and a hash-only `script-src`.
export default defineNuxtModule({
  meta: { name: 'static-ui-colors' },
  setup(_options, nuxt) {
    nuxt.hook('app:resolve', (app) => {
      app.plugins = app.plugins.filter(p => !/@nuxt[\\/]ui[\\/]dist[\\/]runtime[\\/]plugins[\\/]colors/.test(p.src))
    })
  },
})
