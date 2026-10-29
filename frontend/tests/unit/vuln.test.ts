// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  advisoryUrl, ageLabel, cpeLabel, formatAge, ghsaUrl, isAdvisoryId, nvdUrl, packageLabel, safeReferenceUrl, sourceLabel, upgradeHint,
} from '~/utils/vuln'

describe('advisory links are only built from strictly valid ids', () => {
  it('CVE ids link to NVD only for ^CVE-[0-9]{4}-[0-9]{4,19}$', () => {
    expect(nvdUrl('CVE-2023-46734')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2023-46734')
    expect(nvdUrl('CVE-2021-1234567890123456789')).not.toBeNull()
    for (const bad of ['CVE-2023-123', 'cve-2023-46734', 'CVE-23-46734', 'CVE-2023-46734/../x', 'CVE-2023-46734?x=1', ' CVE-2023-46734', 'CVE-2023-46734\n', 'javascript:alert(1)', '', 'CVE-2023-<b>1</b>']) {
      expect(nvdUrl(bad), bad).toBeNull()
    }
  })

  it('GHSA ids link to GitHub only for the exact pattern (case-insensitive)', () => {
    expect(ghsaUrl('GHSA-q847-2q57-wmr3')).toBe('https://github.com/advisories/GHSA-q847-2q57-wmr3')
    expect(ghsaUrl('ghsa-q847-2q57-wmr3')).not.toBeNull()
    for (const bad of ['GHSA-q847-2q57', 'GHSA-q847-2q57-wmr31', 'GHSA-q841-2q57-wmr3', 'GHSA-q847-2q57-wmr3/x', 'GHSA-<b>bad</b>', 'GHSA-q847-2q57-wmr3\n']) {
      expect(ghsaUrl(bad), bad).toBeNull()
    }
  })

  it('other advisory ids (RUSTSEC, GO, PYSEC) are searchable but never linked', () => {
    expect(advisoryUrl('RUSTSEC-2021-0001')).toBeNull()
    expect(advisoryUrl('GO-2021-0001')).toBeNull()
    expect(advisoryUrl('CVE-2021-0001')).not.toBeNull()
    expect(advisoryUrl('GHSA-q847-2q57-wmr3')).not.toBeNull()
  })

  it('isAdvisoryId decides between the exact cve= filter and a text search', () => {
    for (const ok of ['CVE-2023-46734', ' cve-2023-46734 ', 'GHSA-q847-2q57-wmr3', 'RUSTSEC-2021-0001', 'GO-2021-0001']) expect(isAdvisoryId(ok), ok).toBe(true)
    for (const no of ['CVE-2023', 'lodash', 'CVE', '', 'CVE-2023-46734 x', '<script>']) expect(isAdvisoryId(no), no).toBe(false)
  })
})

describe('references', () => {
  it('only absolute http and https URLs without credentials are linkable', () => {
    expect(safeReferenceUrl('https://symfony.com/cve-2023-46734')).toBe('https://symfony.com/cve-2023-46734')
    expect(safeReferenceUrl('http://example.com/a?b=1')).toBe('http://example.com/a?b=1')
    for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>alert(1)</script>', 'ftp://files.example.com/x', 'file:///etc/passwd', '//evil.example.com/x', '/relative/path', 'https://user:pw@evil.example.com/', 'not a url', '', 'vbscript:x']) {
      expect(safeReferenceUrl(bad), bad).toBeNull()
    }
    expect(safeReferenceUrl(`https://example.com/${'a'.repeat(3000)}`)).toBeNull()
  })
})

describe('labels', () => {
  it('formats packages, fixes and sources', () => {
    expect(packageLabel({ ecosystem: 'npm', name: 'lodash', version: '4.17.15' })).toBe('lodash@4.17.15')
    expect(packageLabel({ product: 'nginx', version: '1.18.0' })).toBe('nginx 1.18.0')
    expect(packageLabel({ name: 'x' })).toBe('x')
    expect(packageLabel(null)).toBe('')
    // DAST products are CPE prefixes
    expect(packageLabel({ product: 'cpe:2.3:a:apache:http_server', version: '2.4.41' })).toBe('apache http_server 2.4.41')
    expect(packageLabel({ product: 'cpe:2.3:a:nginx:nginx', version: '1.18.0' })).toBe('nginx 1.18.0')
    expect(packageLabel({ product: 'cpe:2.3:a:php:php' })).toBe('php')
    expect(packageLabel({ product: 'cpe:2.3:a:vendor:thing:1.0:*:*:*:*:*:*:*', version: '1.0' })).toBe('vendor thing 1.0')
    expect(upgradeHint({ fixed_versions: ['4.17.21'] })).toBe('Upgrade to 4.17.21')
    expect(upgradeHint({ fixed_versions: ['5.4.31', '6.3.8'] })).toBe('Upgrade to 5.4.31 or 6.3.8')
    expect(upgradeHint({ fixed_versions: [] })).toBeNull()
    expect(sourceLabel('osv')).toBe('OSV')
    expect(sourceLabel('nvd')).toBe('NVD')
    expect(sourceLabel(null)).toBe('')
  })

  it('cpeLabel only rewrites well-formed CPE 2.3 prefixes; everything else is left to the caller as is', () => {
    expect(cpeLabel('cpe:2.3:a:apache:http_server')).toBe('apache http_server')
    expect(cpeLabel('cpe:2.3:o:linux:linux_kernel')).toBe('linux linux_kernel')
    expect(cpeLabel('cpe:2.3:a:nginx:nginx')).toBe('nginx')
    for (const bad of ['nginx', 'cpe:2.2:a:x:y', 'cpe:2.3:a:onlyvendor', 'cpe:2.3:z:x:y', 'cpe:2.3:a:<b>x</b>:y', 'cpe:2.3:a:x y:z', '', 'CPE:2.3:a:x:y']) {
      expect(cpeLabel(bad), bad).toBeNull()
    }
    expect(cpeLabel(null)).toBeNull()
    expect(packageLabel({ product: 'cpe:2.3:a:<b>x</b>:y', version: '1' })).toBe('cpe:2.3:a:<b>x</b>:y 1')
  })

  it('formatAge gives a coarse human age', () => {
    const now = Date.parse('2026-10-28T12:00:00Z')
    expect(formatAge('2026-10-28T11:59:40Z', now)).toBe('just now')
    expect(formatAge('2026-10-28T11:55:00Z', now)).toBe('5 minutes ago')
    expect(formatAge('2026-10-28T09:00:00Z', now)).toBe('3 hours ago')
    expect(formatAge('2026-10-27T12:00:00Z', now)).toBe('1 day ago')
    expect(formatAge('2026-10-20T12:00:00Z', now)).toBe('8 days ago')
    expect(formatAge(null, now)).toBe('')
    expect(formatAge('garbage', now)).toBe('')
  })

  it('ageLabel prefers the CLI age_days and falls back to the timestamp', () => {
    const now = Date.parse('2026-10-28T12:00:00Z')
    expect(ageLabel(2, '2026-10-01T00:00:00Z', now)).toBe('2 days ago')
    expect(ageLabel(1, null, now)).toBe('1 day ago')
    expect(ageLabel(0, null, now)).toBe('today')
    expect(ageLabel(null, '2026-10-20T12:00:00Z', now)).toBe('8 days ago')
    expect(ageLabel(null, null, now)).toBe('')
    expect(ageLabel(undefined, undefined, now)).toBe('')
  })
})
