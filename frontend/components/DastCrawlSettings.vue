<script setup lang="ts">
import { hasDastAccess } from '~/utils/permissions'
import {
  BUILT_IN_EXCLUSIONS_NOTE, CRAWL_LIMITS_NOTE, DEFAULT_CRAWL, MAX_CRAWL_DEPTH, MAX_CRAWL_PAGES, MAX_EXCLUDE_LENGTH, MAX_EXCLUDE_PATTERNS, crawlFieldErrors,
} from '~/utils/dastAuth'
import type { Codebase } from '~/types/api'

// "Crawling" panel of a URL target. After the (optional) login the engine follows links on the same origin with
// GET requests only, up to the depth and page limits, and skips paths matching the exclusion patterns.
const props = defineProps<{ codebase: Codebase }>()
const emit = defineEmits<{ saved: [] }>()

const auth = useAuth()
const api = useApi()
const toast = useNotify()

const allowed = computed(() => hasDastAccess(auth.user) && props.codebase.target_type === 'url')
const current = computed(() => props.codebase.dast_crawl ?? DEFAULT_CRAWL)

interface Row { key: number, value: string }
let seq = 0
const rowsOf = (list: string[]): Row[] => list.map(value => ({ key: ++seq, value }))

const enabled = ref(current.value.enabled)
const maxDepth = ref<number | string>(current.value.max_depth)
const maxPages = ref<number | string>(current.value.max_pages)
const rows = ref<Row[]>(rowsOf(current.value.exclude))
const busy = ref(false)

const patterns = computed(() => rows.value.map(r => r.value.trim()))
const dirty = computed(() => enabled.value !== current.value.enabled || Number(maxDepth.value) !== current.value.max_depth || Number(maxPages.value) !== current.value.max_pages
  || JSON.stringify(patterns.value) !== JSON.stringify(current.value.exclude))

// Form field names: enabled, max_depth, max_pages, exclude (the list) and exclude[i] (row i). The API calls them dast_crawl_*.
const fe = useFormErrors({
  aliases: { dast_crawl_enabled: 'enabled', dast_crawl_max_depth: 'max_depth', dast_crawl_max_pages: 'max_pages', dast_crawl_exclude: 'exclude' },
  labels: { exclude: 'Excluded paths' },
  validate: () => crawlFieldErrors({ max_depth: maxDepth.value, max_pages: maxPages.value, exclude: rows.value.map(r => r.value) }),
})
fe.autoClear(() => ({ enabled: enabled.value, max_depth: maxDepth.value, max_pages: maxPages.value, ...Object.fromEntries(rows.value.map((r, i) => [`exclude[${i}]`, r.value])), exclude: rows.value.length }))

function addRow() { rows.value = [...rows.value, { key: ++seq, value: '' }] }
function removeRow(key: number) { rows.value = rows.value.filter(r => r.key !== key) }

async function save() {
  if (busy.value || !fe.check()) return
  if (!dirty.value) { toast.info('No changes to save.'); return }
  busy.value = true
  try {
    await api.codebases.patch(props.codebase.id, {
      dast_crawl_enabled: enabled.value, dast_crawl_max_depth: Number(maxDepth.value), dast_crawl_max_pages: Number(maxPages.value), dast_crawl_exclude: patterns.value,
    })
    toast.success('Crawl settings saved.')
    emit('saved')
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UCard v-if="allowed" aria-labelledby="crawl-h" data-testid="dast-crawl" role="region">
    <h2 id="crawl-h" class="mb-1 text-base">Crawling</h2>
    <p class="mb-3 text-muted">Follow links from the start page (after the login, if configured) to find more pages. The crawl is passive: GET requests only, same origin only, within the limits below. {{ CRAWL_LIMITS_NOTE }}</p>
    <form novalidate data-testid="crawl-form" @submit.prevent="save">
      <FormErrorSummary class="mb-4" error-testid="crawl-error" />
      <fieldset :disabled="busy" class="space-y-4">
        <USwitch v-model="enabled" label="Crawl the site during DAST scans" data-testid="crawl-enabled" />
        <div class="grid gap-4 sm:grid-cols-2">
          <AppField label="Max depth" name="max_depth" required :help="`Link hops from the start page, 1 to ${MAX_CRAWL_DEPTH}.`">
            <UInput id="crawl-depth" v-model="maxDepth" type="number" :min="1" :max="MAX_CRAWL_DEPTH" class="w-full" :disabled="!enabled" />
          </AppField>
          <AppField label="Max pages" name="max_pages" required :help="`Pages fetched per scan, 1 to ${MAX_CRAWL_PAGES}.`">
            <UInput id="crawl-pages" v-model="maxPages" type="number" :min="1" :max="MAX_CRAWL_PAGES" class="w-full" :disabled="!enabled" />
          </AppField>
        </div>
        <AppField label="Excluded paths" name="exclude" :hint="`Up to ${MAX_EXCLUDE_PATTERNS}`" :help="`Regular expressions matched against the URL path, at most ${MAX_EXCLUDE_LENGTH} characters each (for example ^/admin or \\.pdf$). ${BUILT_IN_EXCLUSIONS_NOTE}`">
          <div data-testid="crawl-exclude">
            <p v-if="!rows.length" class="text-sm text-muted">No extra patterns.</p>
            <ul class="space-y-2">
              <li v-for="(r, i) in rows" :key="r.key">
                <AppField :name="`exclude[${i}]`" :summary-label="`Excluded path ${i + 1}`">
                  <div class="grid grid-cols-[1fr_auto] items-start gap-2">
                    <UInput v-model="r.value" :aria-label="`Excluded path pattern ${i + 1}`" class="w-full font-mono" placeholder="^/admin" autocomplete="off" spellcheck="false" :disabled="!enabled" />
                    <UButton color="neutral" variant="ghost" icon="i-lucide-x" :aria-label="`Remove pattern ${i + 1}`" :disabled="!enabled" @click="removeRow(r.key)" />
                  </div>
                </AppField>
              </li>
            </ul>
            <UButton v-if="rows.length < MAX_EXCLUDE_PATTERNS" class="mt-2" color="neutral" variant="outline" size="xs" icon="i-lucide-plus" :disabled="!enabled" data-testid="crawl-exclude-add" @click="addRow">Add pattern</UButton>
          </div>
        </AppField>
      </fieldset>
      <div class="mt-4">
        <UButton type="submit" :loading="busy" data-testid="save-crawl">{{ busy ? 'Saving…' : 'Save crawl settings' }}</UButton>
      </div>
    </form>
  </UCard>
</template>
