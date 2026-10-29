<script setup lang="ts">
import { friendlyError } from '~/utils/errors'
import type { ProjectListItem } from '~/types/api'

// Move a Codebase to another Project (scan history and schedule move along).
const props = defineProps<{ open: boolean, codebaseId: number, codebaseName: string, currentProjectId: number }>()
const emit = defineEmits<{ close: [], moved: [projectId: number] }>()

const api = useApi()
const projects = ref<ProjectListItem[]>([])
const state = reactive({ project_id: undefined as number | undefined })
const loading = ref(false)
const busy = ref(false)
const items = computed(() => projects.value.map(p => ({ label: p.name, value: p.id })))

const fe = useFormErrors({
  validate: () => (state.project_id ? {} : { project_id: 'Choose the destination project.' }),
})
fe.autoClear(() => ({ ...state }))

watch(() => props.open, async (o) => {
  if (!o) return
  fe.reset()
  state.project_id = undefined
  loading.value = true
  try {
    const res = await api.projects.list({ page: 1, page_size: 200 })
    projects.value = res.items.filter(p => p.id !== props.currentProjectId)
    state.project_id = projects.value[0]?.id
  } catch (e) {
    fe.formError.value = friendlyError(e).message
  } finally {
    loading.value = false
  }
})

async function submit() {
  if (busy.value || !fe.check()) return
  busy.value = true
  try {
    await api.codebases.patch(props.codebaseId, { project_id: state.project_id! })
    emit('moved', state.project_id!)
  } catch (e) {
    // A name clash is reported on the codebase "name"; the user fixes it by choosing another destination.
    fe.fromServer(e, { fallback: 'project_id', byCode: { name_taken: { field: 'project_id', message: `The destination project already has a codebase named “${props.codebaseName}”.` } } })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalDialog :open="open" :title="`Move ${codebaseName}`" :busy="busy" @close="emit('close')">
    <LoadingState v-if="loading" />
    <UForm v-else id="move-form" :loading-auto="false" :state="state" novalidate class="space-y-4" @submit="submit">
      <p v-if="projects.length === 0" class="text-muted">There is no other project to move this codebase to. Create one first.</p>
      <FormErrorSummary />
      <AppField v-if="projects.length" name="project_id" label="Destination project" required hint="The codebase keeps its full scan history.">
        <USelect id="move-target" v-model="state.project_id" :items="items" class="w-full" data-autofocus placeholder="Choose a project" />
      </AppField>
    </UForm>
    <template #footer>
      <UButton color="neutral" variant="outline" :disabled="busy" @click="emit('close')">Cancel</UButton>
      <UButton type="submit" form="move-form" :disabled="loading || projects.length === 0" :loading="busy">{{ busy ? 'Moving…' : 'Move codebase' }}</UButton>
    </template>
  </ModalDialog>
</template>
