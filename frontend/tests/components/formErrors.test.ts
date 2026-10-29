import { afterEach, describe, expect, it } from 'vitest'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import Harness from '../helpers/FormHarness.vue'
import type { FormErrors } from '~/composables/useFormErrors'
import { ApiError } from '~/utils/errors'

// The shared layer of per-field errors: store, AppField (error under the input, aria), summary, focus, server mapping.

const apiErr = (status: number, code: string, message: string, details?: unknown) => new ApiError({ status, code, message, details })

async function mountHarness() {
  const w = await mountSuspended(Harness, { attachTo: document.body })
  const vm = w.vm as unknown as { fe: FormErrors, state: { name: string, repo_url: string, branch: string } }
  return { w, fe: vm.fe, state: vm.state }
}

afterEach(() => { document.body.innerHTML = '' })

describe('useFormErrors + AppField', () => {
  it('shows every missing or wrong field at once on submit, with the required marker and the label', async () => {
    const { w } = await mountHarness()
    expect(w.find('[data-field="name"]').text()).toContain('Name')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[data-field="name"]').text()).toContain('Name is required.')
    expect(w.find('[data-field="repo_url"]').text()).toContain('Repository URL is required.')
    expect(w.find('[data-field="branch"]').text()).not.toContain('must not contain')
  })

  it('moves focus to the first field with an error (page order)', async () => {
    const { w, state } = await mountHarness()
    state.name = 'ok'
    await flushPromises()
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(document.activeElement?.id).toBe('f-repo')
    state.name = ''
    await flushPromises()
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(document.activeElement?.id).toBe('f-name')
  })

  it('marks the input invalid and ties it to the message (aria-invalid, aria-describedby)', async () => {
    const { w } = await mountHarness()
    expect(w.find('#f-name').attributes('aria-invalid')).toBe('false')
    await w.find('form').trigger('submit')
    await flushPromises()
    const input = w.find('#f-name')
    expect(input.attributes('aria-invalid')).toBe('true')
    const ids = (input.attributes('aria-describedby') ?? '').split(' ')
    const errorEl = ids.map(id => document.getElementById(id)).find(el => el?.textContent?.includes('Name is required.'))
    expect(errorEl).toBeTruthy()
    // the field without an error stays valid
    expect(w.find('#f-branch').attributes('aria-invalid')).toBe('false')
  })

  it('lists the errors in a role="alert" summary with a link per field that focuses it', async () => {
    const { w } = await mountHarness()
    await w.find('form').trigger('submit')
    await flushPromises()
    const summary = w.find('[data-testid="form-errors"]')
    expect(summary.attributes('role')).toBe('alert')
    expect(summary.text()).toContain('Fix these 2 fields to continue')
    expect(summary.text()).toContain('Name: Name is required.')
    expect(summary.text()).toContain('Repository URL: Repository URL is required.')
    await w.find('[data-testid="error-link-repo_url"]').trigger('click')
    expect(document.activeElement?.id).toBe('f-repo')
  })

  it('clears the error of a field when the user changes it, and only that field', async () => {
    const { w, fe } = await mountHarness()
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(Object.keys(fe.errors.value).sort()).toEqual(['name', 'repo_url'])
    await w.find('#f-name').setValue('shop')
    await flushPromises()
    expect(fe.errorFor('name')).toBeUndefined()
    expect(fe.errorFor('repo_url')).toBe('Repository URL is required.')
    expect(w.find('[data-field="name"]').text()).not.toContain('Name is required.')
    expect(w.find('[data-testid="form-errors"]').text()).not.toContain('Name is required.')
    await w.find('#f-repo').setValue('https://git.example.com/x.git')
    await flushPromises()
    expect(fe.hasErrors.value).toBe(false)
    expect(w.find('[data-testid="form-errors"]').exists()).toBe(false)
  })

  it('validates a field when it loses focus, but never hides an error that is already shown', async () => {
    const { w, fe } = await mountHarness()
    await w.find('#f-repo').setValue('http://insecure.example.com')
    await w.find('#f-repo').trigger('focusout')
    await flushPromises()
    expect(fe.errorFor('repo_url')).toBe('Use an https:// URL.')
    expect(fe.errorFor('name')).toBeUndefined() // not touched yet: no error
    await w.find('#f-name').trigger('focusout')
    await flushPromises()
    expect(fe.errorFor('name')).toBe('Name is required.')
  })

  it('maps a server error with details.field to that field (the alias table renames API fields)', async () => {
    const { w, fe } = await mountHarness()
    expect(fe.fromServer(apiErr(422, 'validation_failed', 'git_branch must match ^[A-Za-z0-9._/-]{1,200}$.', { field: 'git_branch' }))).toBe(true)
    await flushPromises()
    expect(fe.errorFor('branch')).toContain('must match')
    expect(w.find('[data-field="branch"]').text()).toContain('must match')
    expect(document.activeElement?.id).toBe('f-branch')
  })

  it('maps several server errors at once, in page order, and keeps unknown fields in the form-level message', async () => {
    const { w, fe } = await mountHarness()
    fe.fromServer(apiErr(422, 'validation_failed', 'repo_url is required.', {
      field: 'repo_url',
      fields: [{ field: 'repo_url', message: 'repo_url is required.' }, { field: 'name', message: 'name is required.' }, { field: 'schedule_cron', message: 'Cron is wrong.' }],
    }))
    await flushPromises()
    expect(fe.errorFor('name')).toBe('name is required.')
    expect(fe.errorFor('repo_url')).toBe('repo_url is required.')
    expect(fe.formError.value).toBe('Cron is wrong.')
    expect(fe.summary.value.map(i => i.name)).toEqual(['name', 'repo_url'])
    expect(document.activeElement?.id).toBe('f-name')
    expect(w.find('[data-testid="form-error"]').text()).toBe('Cron is wrong.')
  })

  it('falls back to the start of the message when the server sends no details', async () => {
    const { fe } = await mountHarness()
    expect(fe.fromServer(apiErr(422, 'validation_failed', 'repo_url is required.'))).toBe(true)
    expect(fe.errorFor('repo_url')).toBe('repo_url is required.')
  })

  it('shows errors that are not about a field (500, 403, network, 404) in the form, not on a field', async () => {
    const { w, fe } = await mountHarness()
    for (const [status, code] of [[500, 'internal'], [403, 'forbidden_role'], [0, 'network_error'], [404, 'not_found']] as const) {
      expect(fe.fromServer(apiErr(status, code, 'x', { field: 'name' }))).toBe(false)
      await flushPromises()
      expect(Object.keys(fe.errors.value)).toEqual([])
      expect(w.find('[data-testid="form-error"]').exists()).toBe(true)
    }
    expect(fe.formError.value).toBe('We could not find what you were looking for. It may have been deleted or moved.')
  })

  it('a new submit replaces the old errors', async () => {
    const { w, fe, state } = await mountHarness()
    fe.fromServer(apiErr(500, 'internal', 'x'))
    state.name = 'n'
    state.repo_url = 'https://git.example.com/x.git'
    await flushPromises()
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(fe.hasErrors.value).toBe(false)
  })
})
