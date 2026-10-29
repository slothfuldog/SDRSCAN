<script setup lang="ts">
import { validateName } from '~/utils/validators'
import type { Project } from '~/types/api'

// Create or edit a Project (name 1-100 characters, description up to 1000).
const props = defineProps<{ open: boolean, project?: Project | null }>()
const emit = defineEmits<{ close: [], saved: [Project] }>()

const api = useApi()
const state = reactive({ name: '', description: '' })
const busy = ref(false)

const fe = useFormErrors({
  validate: () => {
    const errors: Record<string, string> = {}
    const n = validateName(state.name)
    if (n) errors.name = n
    if (state.description.length > 1000) errors.description = 'description must be at most 1000 characters.'
    return errors
  },
})
fe.autoClear(() => ({ ...state }))

watch(() => props.open, (o) => {
  if (!o) return
  state.name = props.project?.name ?? ''
  state.description = props.project?.description ?? ''
  fe.reset()
})

async function submit() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    const body = { name: state.name.trim(), description: state.description.trim() }
    const saved = props.project ? await api.projects.patch(props.project.id, body) : await api.projects.create(body)
    emit('saved', saved)
  } catch (e) {
    fe.fromServer(e, { byCode: { name_taken: 'name' } })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" :title="project ? 'Edit project' : 'Create project'" :busy="busy" @close="emit('close')">
    <UForm id="project-form" :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="submit">
      <FormErrorSummary />
      <AppField name="name" label="Name" required help="1 to 100 characters. Unique among projects.">
        <UInput id="project-name" v-model="state.name" data-autofocus maxlength="100" class="w-full" :disabled="busy" />
      </AppField>
      <AppField name="description" label="Description" hint="Optional">
        <UTextarea id="project-desc" v-model="state.description" :rows="3" :maxlength="1000" class="w-full" :disabled="busy" />
      </AppField>
    </UForm>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton type="submit" form="project-form" :loading="busy">{{ busy ? 'Saving…' : (project ? 'Save changes' : 'Create project') }}</UButton>
    </template>
  </ModalDialog>
</template>
