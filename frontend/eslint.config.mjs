// @ts-check
import withNuxt from './.nuxt/eslint.config.mjs'

export default withNuxt(
  {
    rules: {
      // Security rule from the TRD: snippets, evidence and messages are always rendered as text.
      'vue/no-v-html': 'error',
      // Query-string helpers delete computed keys on purpose.
      '@typescript-eslint/no-dynamic-delete': 'off',
      // `void` is the honest response type of 204 endpoints.
      '@typescript-eslint/no-invalid-void-type': 'off',
    },
  },
)
