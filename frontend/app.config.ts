// Severity colours are Nuxt UI colour aliases, so UBadge/UAlert variants work for them (text is always shown too).
// The list lives in config/uiColors.ts because its CSS is generated statically (see there).
import { UI_COLORS } from './config/uiColors'

export default defineAppConfig({ ui: { colors: { ...UI_COLORS } } })
