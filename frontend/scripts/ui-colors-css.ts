// Build-time generator for assets/css/ui-colors.css (not part of the app bundle).
import colors from 'tailwindcss/colors'

const shades = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950]
const palette = colors as unknown as Record<string, Record<number, string> | string>

function getColor(color: string, shade: number): string {
  const c = palette[color]
  return c && typeof c === 'object' && shade in c ? c[shade]! : ''
}

/** Same output as the runtime plugin of @nuxt/ui (`plugins/colors.js`), for the given aliases. */
export function generateUiColorsCss(map: Record<string, string>): string {
  const { neutral: _neutral, ...rest } = map
  const shadesFor = (key: string, value: string) => shades.map(s => `--ui-color-${key}-${s}: var(--color-${value === 'neutral' ? 'old-neutral' : value}-${s}, ${getColor(value, s)});`).join('\n  ')
  const use = (key: string, shade: number) => `--ui-${key}: var(--ui-color-${key}-${shade});`
  return `@layer base {
  :root {
  ${Object.entries(map).map(([k, v]) => shadesFor(k, v)).join('\n  ')}
  }
  :root, .light {
  ${Object.keys(rest).map(k => use(k, 500)).join('\n  ')}
  }
  .dark {
  ${Object.keys(rest).map(k => use(k, 400)).join('\n  ')}
  }
}
`
}
