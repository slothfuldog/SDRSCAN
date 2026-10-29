import type { InjectionKey } from 'vue'
import { friendlyError, isApiError, isPrivateNetworkError } from '~/utils/errors'
import { humanizeField, mapServerError } from '~/utils/formErrors'
import type { FieldMapOptions } from '~/utils/formErrors'

// Per-field errors of one form: client checks, server errors mapped by field, focus handling and the summary.
// Call it once in the component that owns the form: AppField and FormErrorSummary below it pick it up (provide/inject).

export type FieldErrorMap = Record<string, string>

export interface FormErrorsOptions extends FieldMapOptions {
  /** Client-side validation of the whole form: field name -> message (first message per field). Used on submit and on blur. */
  validate?: () => Record<string, string | undefined> | undefined
  /** Summary labels for errors whose field has no AppField (or no label). */
  labels?: Record<string, string>
}

export interface SummaryItem {
  name: string
  label: string
  message: string
}

export interface FromServerOptions {
  /** Field that gets a "private network address" error when the server sent no field. */
  privateNetworkField?: string
  /** Field for a 400/422 error without field details. */
  fallback?: string
  /** Error code -> field (and optionally a message) for servers that send no `details.field` (e.g. name_taken -> name). */
  byCode?: Record<string, string | { field: string, message: string }>
}

export interface FormErrors {
  /** Unique id of this form; AppField writes it to `data-form`. */
  readonly scope: string
  readonly errors: Readonly<Ref<FieldErrorMap>>
  /** An error that belongs to no field (403, 404, 500, network, or a field the form does not have). */
  readonly formError: Ref<string | null>
  readonly hasErrors: ComputedRef<boolean>
  /** Errors in the order of the fields on the page. */
  readonly summary: ComputedRef<SummaryItem[]>
  errorFor: (name: string) => string | undefined
  set: (name: string, message: string) => void
  setMany: (map: FieldErrorMap) => void
  clear: (name: string) => void
  clearAll: () => void
  /** Clears everything, also the touched state (use when a dialog opens). */
  reset: () => void
  /** Runs `validate`, shows every error at once and focuses the first field. True when the form is valid. */
  check: () => boolean
  /** A field lost focus: show its client error (never hides one that is already shown). */
  blur: (name: string) => void
  /** Clears the error of every field whose value changed. `source` returns name -> value of the form's fields. */
  autoClear: (source: () => Record<string, unknown>) => void
  /** Maps a failed request onto the fields. True when at least one field got the error; the rest goes to `formError`. */
  fromServer: (e: unknown, opts?: FromServerOptions) => boolean
  focusField: (name: string) => boolean
  focusFirst: () => boolean
  // used by AppField
  register: (name: string, label: string | undefined) => void
  unregister: (name: string) => void
  has: (name: string) => boolean
}

export const FORM_ERRORS_KEY: InjectionKey<FormErrors> = Symbol('sdrscan.form-errors')

let scopeSeq = 0

const FOCUSABLE = 'input:not([type="hidden"]):not([disabled]), textarea:not([disabled]), select:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function useFormErrors(options: FormErrorsOptions = {}): FormErrors {
  const scope = `form${++scopeSeq}`
  const errors = ref<FieldErrorMap>({})
  const formError = ref<string | null>(null)
  const labels = ref<Record<string, string | undefined>>({})
  const touched = new Set<string>()

  const mapOptions = (): FieldMapOptions => ({ aliases: options.aliases, fields: options.fields, has: (n: string) => n in labels.value || !!options.has?.(n) })

  const fieldEls = (): HTMLElement[] => (typeof document === 'undefined' ? [] : [...document.querySelectorAll<HTMLElement>(`[data-form="${scope}"][data-field]`)])

  /** Names ordered like the fields on the page; names without a field in the DOM keep their insertion order at the end. */
  function ordered(names: string[]): string[] {
    const domOrder = fieldEls().map(el => el.getAttribute('data-field')!)
    const rank = (n: string) => { const i = domOrder.indexOf(n); return i === -1 ? Number.MAX_SAFE_INTEGER : i }
    return [...names].sort((a, b) => rank(a) - rank(b))
  }

  const summary = computed<SummaryItem[]>(() => ordered(Object.keys(errors.value)).map(name => ({
    name, label: labels.value[name] || options.labels?.[name] || humanizeField(name), message: errors.value[name]!,
  })))
  const hasErrors = computed(() => Object.keys(errors.value).length > 0 || !!formError.value)

  const errorFor = (name: string) => errors.value[name]
  const set = (name: string, message: string) => { errors.value = { ...errors.value, [name]: message } }
  const setMany = (map: FieldErrorMap) => { errors.value = { ...errors.value, ...map } }
  function clear(name: string) {
    if (!(name in errors.value)) return
    const next = { ...errors.value }
    delete next[name]
    errors.value = next
  }
  const clearAll = () => { errors.value = {}; formError.value = null }
  function reset() { clearAll(); touched.clear() }

  function focusField(name: string): boolean {
    const el = fieldEls().find(x => x.getAttribute('data-field') === name)
    if (!el) return false
    const target = el.matches(FOCUSABLE) ? el : el.querySelector<HTMLElement>(FOCUSABLE)
    ;(el as HTMLElement & { scrollIntoView?: (o?: ScrollIntoViewOptions) => void }).scrollIntoView?.({ block: 'center', behavior: 'smooth' })
    if (!target) return false
    target.focus({ preventScroll: true })
    return true
  }
  function focusFirst(): boolean {
    for (const name of ordered(Object.keys(errors.value))) if (focusField(name)) return true
    return false
  }

  /** The client validation as a plain name -> message map (empty values dropped). */
  function runValidate(): FieldErrorMap {
    const out: FieldErrorMap = {}
    for (const [k, v] of Object.entries(options.validate?.() ?? {})) if (v) out[k] = v
    return out
  }

  function check(): boolean {
    formError.value = null
    const found = runValidate()
    errors.value = { ...found }
    for (const k of Object.keys(found)) touched.add(k)
    if (!Object.keys(found).length) return true
    void nextTick(focusFirst)
    return false
  }

  function blur(name: string) {
    touched.add(name)
    if (!options.validate || errors.value[name]) return
    const found = runValidate()
    if (found[name]) set(name, found[name]!)
  }

  function autoClear(source: () => Record<string, unknown>) {
    watch(source, (cur, prev) => {
      if (!prev) return
      for (const k of new Set([...Object.keys(cur), ...Object.keys(prev)])) {
        if (cur[k] !== prev[k]) clear(k)
      }
    })
  }

  function fromServer(e: unknown, opts: FromServerOptions = {}): boolean {
    const mapped = mapServerError(e, mapOptions())
    let fields = mapped.fields
    let messages = [...mapped.unmapped]
    const coded = isApiError(e) ? opts.byCode?.[e.code] : undefined
    if (!fields.length && coded) {
      const c = typeof coded === 'string' ? { field: coded, message: (e as { message: string }).message } : coded
      fields = [{ name: c.field, message: c.message, apiField: c.field }]
      messages = []
    }
    if (!fields.length && opts.privateNetworkField && isPrivateNetworkError(e)) fields = [{ name: opts.privateNetworkField, message: friendlyError(e).message, apiField: opts.privateNetworkField }]
    if (!fields.length && opts.fallback && isApiError(e) && (e.status === 422 || e.status === 400)) { fields = [{ name: opts.fallback, message: e.message, apiField: opts.fallback }]; messages = [] }
    const next: FieldErrorMap = {}
    for (const f of fields) if (!(f.name in next)) next[f.name] = f.message
    errors.value = next
    formError.value = null
    if (!fields.length) {
      formError.value = messages.length ? messages.join(' ') : friendlyError(e).message
      return false
    }
    if (messages.length) formError.value = messages.join(' ')
    void nextTick(focusFirst)
    return true
  }

  const register = (name: string, label: string | undefined) => { labels.value = { ...labels.value, [name]: label } }
  function unregister(name: string) {
    if (!(name in labels.value)) return
    const next = { ...labels.value }
    delete next[name]
    labels.value = next
    clear(name)
  }

  const api: FormErrors = {
    scope, errors, formError, hasErrors, summary, errorFor, set, setMany, clear, clearAll, reset, check, blur, autoClear, fromServer, focusField, focusFirst,
    register, unregister, has: (n: string) => n in labels.value,
  }
  provide(FORM_ERRORS_KEY, api)
  return api
}
