<script setup lang="ts">
useHead({ title: 'Add codebase · SDRScan' })

const api = useApi()
const route = useRoute()
const toast = useNotify()

const { data: projects, error, pending, reload } = useLoad(() => api.projects.list({ page: 1, page_size: 200 }))
const chosen = ref<number | undefined>(Number(route.query.project) || undefined)
const project = computed(() => projects.value?.items.find(p => p.id === chosen.value))
const items = computed(() => (projects.value?.items ?? []).map(p => ({ label: p.name, value: p.id })))

watch(projects, (p) => {
  if (p && !chosen.value) chosen.value = p.items[0]?.id
})

async function saved(cb: { id: number, name: string }) {
  toast.success(`Codebase "${cb.name}" added.`)
  await navigateTo(`/codebases/${cb.id}`)
}
</script>

<template>
  <div class="max-w-3xl">
    <PageHeader title="Add codebase">
      <template #breadcrumb>
        <AppBreadcrumb :items="[{ label: 'Projects', to: '/' }, project ? { label: project.name, to: `/projects/${project.id}` } : { label: 'Project' }, { label: 'Add codebase' }]" />
      </template>
    </PageHeader>
    <LoadingState v-if="pending && !projects" />
    <ErrorState v-else-if="error && !projects" :error="error" @retry="reload" />
    <template v-else-if="projects">
      <EmptyState v-if="projects.items.length === 0" title="Create a project first" hint="A codebase always belongs to a project.">
        <UButton to="/">Go to Projects</UButton>
      </EmptyState>
      <UCard v-else>
        <UFormField class="mb-5 max-w-sm" label="Project" name="project">
          <USelect id="cb-project" v-model="chosen" :items="items" class="w-full" />
        </UFormField>
        <CodebaseForm v-if="chosen" :key="chosen" mode="create" :project-id="chosen" @saved="saved">
          <template #actions>
            <UButton :to="chosen ? `/projects/${chosen}` : '/'" color="neutral" variant="outline">Cancel</UButton>
          </template>
        </CodebaseForm>
      </UCard>
    </template>
  </div>
</template>
