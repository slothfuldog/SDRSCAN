<script setup lang="ts">
// Wraps Admin pages. Members opening the URL directly see a message (the API answers 403 anyway).
const auth = useAuth()
</script>

<template>
  <slot v-if="auth.isAdmin" />
  <UAlert
    v-else color="warning" variant="subtle" icon="i-lucide-lock" title="You do not have access to this page." description="Ask an Admin if you need it."
    :actions="[{ label: 'Back to Projects', to: '/', color: 'neutral', variant: 'outline', size: 'xs' }]" role="alert" data-testid="no-access"
  />
</template>
