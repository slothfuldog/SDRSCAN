<template>
  <main class="grid min-h-screen place-items-center px-4 py-10">
    <div class="w-full max-w-sm">
      <div class="mb-6 flex items-center justify-center gap-2 text-xl font-semibold text-highlighted">
        <span class="grid size-9 place-items-center rounded-md bg-primary text-inverted"><AppIcon name="shield" :size="20" /></span>
        SDRScan
      </div>
      <slot />
    </div>
  </main>
</template>
