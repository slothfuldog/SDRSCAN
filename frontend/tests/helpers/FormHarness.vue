<script setup lang="ts">
// Test harness: a small form built from the shared pieces (useFormErrors, AppField, FormErrorSummary).
const state = reactive({ name: '', repo_url: '', branch: 'main' })
const fe = useFormErrors({
  aliases: { git_branch: 'branch' },
  validate: () => {
    const e: Record<string, string> = {}
    if (!state.name.trim()) e.name = 'Name is required.'
    if (!state.repo_url.trim()) e.repo_url = 'Repository URL is required.'
    else if (!state.repo_url.startsWith('https://')) e.repo_url = 'Use an https:// URL.'
    if (state.branch.includes(' ')) e.branch = 'Branch must not contain spaces.'
    return e
  },
})
fe.autoClear(() => ({ ...state }))
defineExpose({ fe, state })
</script>

<template>
  <form novalidate @submit.prevent="fe.check()">
    <FormErrorSummary />
    <AppField name="name" label="Name" required><UInput id="f-name" v-model="state.name" /></AppField>
    <AppField name="repo_url" label="Repository URL" required help="https://host/path"><UInput id="f-repo" v-model="state.repo_url" /></AppField>
    <AppField name="branch" label="Branch"><UInput id="f-branch" v-model="state.branch" /></AppField>
    <button type="submit">Save</button>
  </form>
</template>
