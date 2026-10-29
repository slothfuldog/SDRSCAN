<script setup lang="ts">
useHead({ title: 'Page not found · SDRScan' })
</script>

<template>
  <div class="mx-auto max-w-md py-16 text-center" data-testid="not-found">
    <p class="text-5xl font-bold text-dimmed">404</p>
    <h1 class="mt-2">Page not found</h1>
    <p class="mt-1 text-muted">The page you are looking for does not exist or was moved.</p>
    <UButton to="/" class="mt-4">Back to Projects</UButton>
  </div>
</template>
