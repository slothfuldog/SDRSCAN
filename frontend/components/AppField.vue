<script setup lang="ts">
import { FORM_ERRORS_KEY } from '~/composables/useFormErrors'

// A form field with its per-field error under the input (UFormField + the form's error store).
// - `name` is the name of the field in the form (see useFormErrors); the server's `details.field` is mapped to it.
// - `required` shows the required marker next to the label.
// - The error appears below the input; UFormField links it with aria-describedby and sets aria-invalid on the input.
// - Leaving the field (focusout) runs the client check for this field.
const props = defineProps<{
  name: string
  label?: string
  /** Label used in the error summary when the field has none of its own (rows of a list). */
  summaryLabel?: string
  required?: boolean
  hint?: string
  help?: string
  description?: string
}>()

const fe = inject(FORM_ERRORS_KEY, null)
const error = computed(() => fe?.errorFor(props.name))
const registeredLabel = computed(() => props.summaryLabel || props.label)

onMounted(() => {
  if (!fe) return
  watch(() => [props.name, registeredLabel.value] as const, ([name, label], old) => {
    if (old && old[0] !== name) fe.unregister(old[0])
    fe.register(name, label)
  }, { immediate: true })
})
onBeforeUnmount(() => fe?.unregister(props.name))
</script>

<template>
  <UFormField
    :name="name" :label="label" :required="required" :hint="hint" :help="help" :description="description" :error="error"
    :data-form="fe?.scope" :data-field="name" @focusout="fe?.blur(name)"
  >
    <slot :error="error" />
  </UFormField>
</template>
