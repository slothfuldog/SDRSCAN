// SDRScan frontend: Nuxt 3 SPA (ssr: false), built with `nuxt generate` and embedded into sdrscan-backend.
// All API calls use the relative path /api/v1 (one origin, no CORS).
const apiTarget = process.env.SDRSCAN_API_URL || 'http://127.0.0.1:8080'

export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  ssr: false,
  devtools: { enabled: false },
  telemetry: false,

  modules: ['@nuxt/ui', '@pinia/nuxt', '@nuxt/eslint'],

  css: ['~/assets/css/main.css'],

  // Nuxt UI: no external fonts (Public Sans is bundled from @fontsource-variable) and no colour-mode module
  // (it injects an inline script). Dark mode follows the system through plugins/color-scheme.client.ts.
  ui: {
    fonts: false,
    colorMode: false,
    theme: { colors: ['primary', 'secondary', 'success', 'info', 'warning', 'error', 'neutral', 'critical', 'high', 'medium', 'low', 'notice'] },
  },

  // Icons are bundled locally (@iconify-json/lucide): no request to api.iconify.design, works on closed networks.
  icon: {
    // svg mode renders inline <svg> from the local bundle; the default css mode injects a <style> at runtime (blocked by a strict CSP).
    mode: 'svg',
    provider: 'none',
    fallbackToApi: false,
    serverBundle: 'local',
    clientBundle: {
      scan: true,
      icons: [
        // used by Nuxt UI components themselves
        'lucide:arrow-down', 'lucide:arrow-up', 'lucide:arrow-left', 'lucide:arrow-right', 'lucide:check', 'lucide:chevron-down', 'lucide:chevron-left',
        'lucide:chevron-right', 'lucide:chevron-up', 'lucide:chevrons-left', 'lucide:chevrons-right', 'lucide:ellipsis', 'lucide:circle-alert',
        'lucide:circle-check', 'lucide:circle-x', 'lucide:info', 'lucide:loader-circle', 'lucide:minus', 'lucide:search', 'lucide:x', 'lucide:menu',
        'lucide:copy', 'lucide:copy-check', 'lucide:triangle-alert', 'lucide:external-link', 'lucide:ellipsis-vertical',
      ],
    },
  },

  app: {
    baseURL: '/',
    head: {
      htmlAttrs: { lang: 'en' },
      title: 'SDRScan',
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'color-scheme', content: 'light dark' },
        { name: 'referrer', content: 'no-referrer' },
      ],
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    },
  },

  runtimeConfig: {
    public: {
      // Relative on purpose: the backend serves the UI and the API from the same origin.
      apiBase: '/api/v1',
    },
  },

  features: { inlineStyles: false },
  experimental: { payloadExtraction: false },

  nitro: ({
    // Development only: forward /api to the backend (real or mock). Host is kept as-is
    // (changeOrigin: false) so the backend's Origin/Host check passes for http://localhost:3000.
    devProxy: {
      '/api': { target: `${apiTarget}/api`, changeOrigin: false },
    },
  }) as never,

  typescript: {
    strict: true,
    typeCheck: false,
    tsConfig: {
      compilerOptions: {
        allowImportingTsExtensions: true,
        noUncheckedIndexedAccess: false,
      },
    },
  },

  eslint: { config: { stylistic: false } },
})
