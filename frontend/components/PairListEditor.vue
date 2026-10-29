<script setup lang="ts">
import { newRow, rowField } from '~/utils/dastAuth'
import type { PairRow } from '~/utils/dastAuth'

// Name / value rows (extra login fields, headers, cookies). Values are write-only: they are typed into a
// password input and never filled in from the server; a row that already has a stored value shows
// "Saved" and keeps it until something is typed.
// Every row is a form field of its own (`<fieldPrefix>.<name>`), so that a problem is shown under the row that has it.
const props = withDefaults(defineProps<{
  label: string
  /** Prefix of the field names of the rows, the API's path: "headers", "cookies" or "login.extra_fields". */
  fieldPrefix: string
  namePlaceholder?: string
  valuePlaceholder?: string
  addLabel: string
  max: number
  testid: string
  disabled?: boolean
  /** A blank value is fine (extra login fields). */
  allowEmptyValue?: boolean
}>(), { namePlaceholder: 'Name', valuePlaceholder: 'Value', disabled: false, allowEmptyValue: false })
const rows = defineModel<PairRow[]>({ required: true })

function add() { rows.value = [...rows.value, newRow()] }
function remove(key: number) { rows.value = rows.value.filter(r => r.key !== key) }
const summaryLabel = (r: PairRow, i: number) => `${props.label} ${i + 1}${r.name.trim() ? ` “${r.name.trim()}”` : ''}`
</script>

<template>
  <div :data-testid="testid" role="group" :aria-label="label">
    <p v-if="!rows.length" class="text-sm text-muted">None.</p>
    <ul class="space-y-2">
      <li v-for="(r, i) in rows" :key="r.key">
        <AppField :name="rowField(fieldPrefix, r)" :summary-label="summaryLabel(r, i)" required>
          <div class="grid grid-cols-[1fr_1fr_auto] items-start gap-2">
            <UInput v-model="r.name" :aria-label="`${label} ${i + 1} name`" :placeholder="namePlaceholder" class="w-full font-mono" autocomplete="off" spellcheck="false" :disabled="disabled || r.stored" />
            <UInput
              v-model="r.value" type="password" :aria-label="`${label} ${i + 1} value`" class="w-full font-mono" autocomplete="new-password" :disabled="disabled"
              :placeholder="r.stored ? 'Saved (leave blank to keep)' : valuePlaceholder"
            />
            <UButton color="neutral" variant="ghost" icon="i-lucide-x" :aria-label="`Remove ${label} ${i + 1}`" :disabled="disabled" @click="remove(r.key)" />
          </div>
        </AppField>
      </li>
    </ul>
    <UButton v-if="rows.length < max" class="mt-2" color="neutral" variant="outline" size="xs" icon="i-lucide-plus" :disabled="disabled" :data-testid="`${testid}-add`" @click="add">{{ addLabel }}</UButton>
    <p v-if="props.allowEmptyValue" class="mt-1 text-xs text-muted">An empty value is sent as an empty string.</p>
  </div>
</template>
