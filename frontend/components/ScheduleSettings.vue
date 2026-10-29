<script setup lang="ts">
import { nextRuns } from '~/utils/cron'
import { displayUser } from '~/utils/format'
import { canEditSchedule } from '~/utils/permissions'
import {
  MIN_INTERVAL_MINUTES, SCHEDULE_PRESETS, describeSchedule, presetFor, scheduleStatusLabel, suspendedReasonText, validateSchedule,
} from '~/utils/schedule'
import type { Codebase } from '~/types/api'
import type { SchedulePresetKey } from '~/utils/schedule'

// Scheduled scans: preset (Hourly / Daily 02:00 UTC / Weekly) or custom cron (UTC), preview of the next three runs,
// status (Active / Suspended), owner, and Resume for suspended schedules. The scheduler runs on the backend.
// The user who sets or resumes a schedule becomes its owner and must be allowed to trigger that scan type
// (URL targets: Admin or DAST access; others see the schedule read-only).
const props = defineProps<{ codebase: Codebase }>()
const emit = defineEmits<{ saved: [] }>()

const auth = useAuth()
const api = useApi()
const toast = useNotify()

const schedule = computed(() => props.codebase.schedule ?? null)
const editable = computed(() => canEditSchedule(auth.user, props.codebase))
const isUrl = computed(() => props.codebase.target_type === 'url')
const minMinutes = computed(() => MIN_INTERVAL_MINUTES[props.codebase.target_type])

const preset = ref<SchedulePresetKey>(schedule.value ? presetFor(schedule.value.cron) : 'daily')
const custom = ref(schedule.value?.cron ?? '*/30 * * * *')
const busy = ref(false)
const deleteOpen = ref(false)

const presetItems = [...SCHEDULE_PRESETS.map(p => ({ label: p.label, value: p.key, description: p.hint })), { label: 'Custom cron', value: 'custom' }]
const cron = computed(() => (preset.value === 'custom' ? custom.value.trim() : SCHEDULE_PRESETS.find(p => p.key === preset.value)!.cron))
const clientError = computed(() => validateSchedule(cron.value, props.codebase.target_type))
const preview = computed(() => (clientError.value ? [] : nextRuns(cron.value, new Date(), 3).map(d => d.toISOString())))
const status = computed(() => scheduleStatusLabel(schedule.value?.status))
const fe = useFormErrors({
  // The preset values are valid; only the custom expression can fail. The API names the field "cron" (a preset has no field: the message goes to the form).
  validate: () => {
    const m = custom.value.trim() === '' && preset.value === 'custom' ? 'Cron expression is required: enter 5 fields, for example 0 2 * * 1 (UTC).' : clientError.value
    return m ? { cron: m } : {}
  },
  labels: { cron: 'Cron expression' },
})
fe.autoClear(() => ({ cron: custom.value, preset: preset.value }))
const unconfirmed = computed(() => isUrl.value && props.codebase.dast?.status !== 'confirmed')

async function run<T>(fn: () => Promise<T>, ok: string) {
  busy.value = true
  fe.formError.value = null
  try {
    await fn()
    toast.success(ok)
    emit('saved')
  } catch (e) {
    fe.fromServer(e)
  } finally {
    busy.value = false
  }
}

async function save() {
  if (busy.value || !fe.check()) return
  await run(() => api.schedules.put(props.codebase.id, cron.value), 'Schedule saved. You are now its owner.')
}

const resume = () => run(() => api.schedules.resume(props.codebase.id), 'Schedule resumed. You are now its owner.')

async function remove() {
  await run(() => api.schedules.remove(props.codebase.id), 'Schedule deleted.')
  deleteOpen.value = false
}
</script>

<template>
  <UCard aria-labelledby="schedule-h" data-testid="schedule" role="region">
    <h2 id="schedule-h" class="mb-1 text-base">Schedule</h2>
    <p class="mb-4 text-muted">Run a full {{ isUrl ? 'DAST' : 'SAST' }} scan automatically. Times are in UTC. The minimum interval is {{ minMinutes }} minutes.</p>

    <div v-if="schedule" class="mb-4 rounded-md border border-default p-3" data-testid="schedule-summary">
      <p class="flex flex-wrap items-center gap-2">
        <UBadge :color="status.tone === 'ok' ? 'success' : 'warning'" variant="subtle" data-testid="schedule-status">{{ status.label }}</UBadge>
        <span>{{ describeSchedule(schedule.cron) }}</span>
      </p>
      <dl class="mt-2 grid grid-cols-[9rem_1fr] gap-y-1">
        <dt class="text-muted">Next run</dt>
        <dd><LocalTime :value="schedule.status === 'suspended' ? null : schedule.next_run_at" empty="None scheduled" /></dd>
        <dt class="text-muted">Last queued</dt>
        <dd><LocalTime :value="schedule.last_enqueued_at" empty="Never" /></dd>
        <template v-if="schedule.owner"><dt class="text-muted">Owner</dt><dd data-testid="schedule-owner">{{ displayUser(schedule.owner) }}</dd></template>
      </dl>
      <UAlert v-if="schedule.status === 'suspended'" class="mt-3" color="warning" variant="subtle" icon="i-lucide-triangle-alert" role="status" data-testid="schedule-suspended" title="This schedule is suspended and will not run.">
        <template #description>
          <p>{{ suspendedReasonText(schedule.suspended_reason) }} <template v-if="schedule.suspended_at">Suspended <LocalTime :value="schedule.suspended_at" />.</template></p>
          <p v-if="editable" class="mt-1">Resuming makes you the new owner of the schedule.</p>
          <UButton v-if="editable" class="mt-2" size="xs" icon="i-lucide-play" :loading="busy" data-testid="resume-schedule" @click="resume">Resume</UButton>
        </template>
      </UAlert>
      <UAlert v-if="unconfirmed" class="mt-3" color="info" variant="subtle" description="DAST schedules only run while the target is confirmed by an Admin. Runs are skipped until then." />
    </div>

    <form novalidate @submit.prevent="save">
      <FormErrorSummary class="mb-3" />
      <fieldset :disabled="busy || !editable">
        <URadioGroup v-model="preset" :legend="schedule ? 'Change frequency' : 'Frequency'" orientation="horizontal" :items="presetItems" />
        <AppField v-if="preset === 'custom'" class="mt-3 max-w-sm" label="Cron expression (5 fields, UTC)" name="cron" required help="For example 0 2 * * 1 (Mondays at 02:00).">
          <UInput id="sched-cron" v-model="custom" class="w-full font-mono" placeholder="0 2 * * 1" spellcheck="false" autocomplete="off" />
        </AppField>
      </fieldset>
      <div class="mt-3" data-testid="schedule-preview" aria-live="polite">
        <p v-if="clientError" class="text-sm text-muted">Enter a valid cron expression to see the next runs.</p>
        <template v-else>
          <p class="text-xs text-muted">Next three runs:</p>
          <ul class="text-sm"><li v-for="t in preview" :key="t"><LocalTime :value="t" /></li></ul>
        </template>
      </div>
      <UAlert v-if="!editable" class="mt-3" color="info" variant="subtle" description="You need DAST access to change the schedule of a URL target. Ask an Admin. You can still view it." />
      <div v-if="editable" class="mt-4 flex flex-wrap gap-2">
        <UButton type="submit" :loading="busy" data-testid="save-schedule">{{ busy ? 'Saving…' : 'Save schedule' }}</UButton>
        <UButton v-if="schedule" color="error" variant="outline" icon="i-lucide-trash-2" :disabled="busy" data-testid="delete-schedule" @click="deleteOpen = true;">Delete schedule</UButton>
      </div>
    </form>

    <ModalDialog :open="deleteOpen" title="Delete schedule" :busy="busy" @close="deleteOpen = false">
      <p>Delete the schedule of <strong>{{ codebase.name }}</strong>? Automatic scans stop. You can set a new schedule later.</p>
      <template #footer>
        <UButton color="neutral" variant="outline" :disabled="busy" @click="deleteOpen = false;">Cancel</UButton>
        <UButton color="error" :loading="busy" data-autofocus @click="remove">Delete schedule</UButton>
      </template>
    </ModalDialog>
  </UCard>
</template>
