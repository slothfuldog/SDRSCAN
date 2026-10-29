/**
 * A ref backed by one query-string parameter, so filters, pages and tabs live in the URL and can be shared.
 * Setting the default value (or undefined) removes the parameter.
 */
type Widen<T> = T extends number ? number : string

export function useRouteQuery<T extends string | number>(
  key: string,
  defaultValue: T,
  opts: { resetPage?: boolean } = {},
) {
  type V = Widen<T>
  const route = useRoute()
  const router = useRouter()
  return computed<V>({
    get() {
      const raw = route.query[key]
      const v = Array.isArray(raw) ? raw[0] : raw
      if (v === undefined || v === null || v === '') return defaultValue as V
      if (typeof defaultValue === 'number') {
        const n = Number(v)
        return (Number.isFinite(n) && n >= 1 ? Math.floor(n) : defaultValue) as V
      }
      return v as V
    },
    set(value: V) {
      const query = { ...route.query }
      if ((value as unknown) === defaultValue || value === undefined || value === '') delete query[key]
      else query[key] = String(value)
      if (opts.resetPage && key !== 'page') delete query.page
      void router.replace({ query })
    },
  })
}
