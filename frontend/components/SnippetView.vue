<script setup lang="ts">
// Renders a code snippet as TEXT only (Vue interpolation escapes everything; v-html is banned by lint).
// file: numbered lines from start_line; every line of the region is highlighted as the problem lines.
// url: evidence block without line numbers.
const props = defineProps<{
  snippet: string
  kind: 'file' | 'url'
  startLine?: number | null
  endLine?: number | null
  startColumn?: number | null
  redacted?: boolean
}>()

const numbered = computed(() => props.kind === 'file' && typeof props.startLine === 'number' && props.startLine > 0)

const rows = computed(() => {
  const lines = props.snippet.replace(/\r\n/g, '\n').split('\n')
  const first = props.startLine ?? 1
  const indent = props.startColumn && props.startColumn > 1 ? ' '.repeat(props.startColumn - 1) : ''
  return lines.map((text, i) => ({
    no: first + i,
    // The snippet is the marked region, not the whole line: the start column is shown as indentation.
    text: i === 0 ? indent + text : text,
    hot: numbered.value ? (props.endLine ? first + i <= Math.max(props.endLine, first) : true) : false,
  }))
})
</script>

<template>
  <div class="overflow-hidden rounded-md border border-default bg-muted" data-testid="snippet">
    <pre class="overflow-x-auto text-xs leading-5" tabindex="0" :aria-label="kind === 'url' ? 'Request and response evidence' : 'Code snippet'"><code
      v-for="(r, i) in rows" :key="i" class="flex"
      :class="r.hot ? 'bg-error/15' : ''"
      :data-hot="r.hot ? 'true' : 'false'"
    ><span v-if="numbered" class="w-12 shrink-0 select-none border-r border-default px-2 text-right tabular-nums text-muted" aria-hidden="true">{{ r.no }}</span><span class="whitespace-pre px-3">{{ r.text }}</span></code></pre>
    <p v-if="redacted" class="flex items-center gap-1 border-t border-default bg-warning/10 px-3 py-1 text-xs text-warning">
      <AppIcon name="lock" :size="12" /> Value hidden. Secret values are replaced with [REDACTED].
    </p>
  </div>
</template>
