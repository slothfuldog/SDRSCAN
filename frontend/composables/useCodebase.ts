import type { InjectionKey, Ref } from 'vue'
import type { Codebase } from '~/types/api'

export interface CodebaseContext {
  codebase: Ref<Codebase | undefined>
  reload: () => Promise<void>
}

export const CODEBASE_KEY: InjectionKey<CodebaseContext> = Symbol('sdrscan.codebase')

/** Child pages of /codebases/[id] read the Codebase loaded by the parent route. */
export function useCodebase(): CodebaseContext {
  const ctx = inject(CODEBASE_KEY)
  if (!ctx) throw new Error('useCodebase() must be used inside a /codebases/[id] page')
  return ctx
}
