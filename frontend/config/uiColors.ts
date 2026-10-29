// Colour aliases of the UI. Nuxt UI normally generates the CSS variables for them at runtime and injects them as an
// inline <style> (plus a small inline <script> that removes a temporary copy). Both are blocked by a strict CSP, so the
// same CSS is generated ahead of time into assets/css/ui-colors.css (npm run gen:ui-colors) and the runtime plugin is
// removed by modules/static-ui-colors.ts. A unit test keeps the file in sync with this list.
export const UI_COLORS = {
  primary: 'blue',
  neutral: 'slate',
  critical: 'red',
  high: 'orange',
  medium: 'amber',
  low: 'sky',
  notice: 'zinc',
} as const
