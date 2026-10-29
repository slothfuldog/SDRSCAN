// @vitest-environment node
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { UI_COLORS } from '../../config/uiColors'
import { generateUiColorsCss } from '../../scripts/ui-colors-css'

describe('static Nuxt UI colours (no runtime inline <style>)', () => {
  it('assets/css/ui-colors.css matches config/uiColors.ts (run `npm run gen:ui-colors` after changing colours)', () => {
    const file = readFileSync(new URL('../../assets/css/ui-colors.css', import.meta.url), 'utf8')
    expect(file.endsWith(generateUiColorsCss(UI_COLORS))).toBe(true)
  })

  it('defines the severity aliases and primary/neutral for light and dark', () => {
    const css = generateUiColorsCss(UI_COLORS)
    for (const k of ['primary', 'critical', 'high', 'medium', 'low', 'notice']) {
      expect(css).toContain(`--ui-color-${k}-500:`)
      expect(css).toContain(`--ui-${k}: var(--ui-color-${k}-500);`)
      expect(css).toContain(`--ui-${k}: var(--ui-color-${k}-400);`)
    }
    expect(css).not.toMatch(/--ui-neutral: /)
  })
})
