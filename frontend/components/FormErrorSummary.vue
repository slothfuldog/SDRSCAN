<script setup lang="ts">
import { FORM_ERRORS_KEY } from '~/composables/useFormErrors'

// The errors of the form in one place, at the top of the form: every field with a problem ("Label: message", a link
// that moves focus to the field) and the error that belongs to no field. It is a live region (role="alert").
const props = withDefaults(defineProps<{ errorTestid?: string, title?: string }>(), { errorTestid: 'form-error', title: undefined })
const fe = inject(FORM_ERRORS_KEY, null)

const items = computed(() => fe?.summary.value ?? [])
const heading = computed(() => props.title ?? (items.value.length === 1 ? 'Fix this field to continue' : `Fix these ${items.value.length} fields to continue`))
const show = computed(() => items.value.length > 0 || !!fe?.formError.value)
</script>

<template>
  <UAlert v-if="fe && show" color="error" variant="subtle" icon="i-lucide-circle-alert" role="alert" data-testid="form-errors" :title="items.length ? heading : undefined">
    <template #description>
      <ul v-if="items.length" class="mt-1 list-disc space-y-0.5 pl-5" data-testid="form-error-list">
        <li v-for="it in items" :key="it.name">
          <button type="button" class="font-medium underline underline-offset-2" :data-testid="`error-link-${it.name}`" @click="fe.focusField(it.name)">{{ it.label }}</button>: {{ it.message }}
        </li>
      </ul>
      <p v-if="fe.formError.value" :class="items.length ? 'mt-2' : ''" :data-testid="errorTestid">{{ fe.formError.value }}</p>
    </template>
  </UAlert>
</template>
