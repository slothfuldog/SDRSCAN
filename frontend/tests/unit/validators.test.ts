// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { PRIVATE_NETWORK_MESSAGE, isAlwaysBlockedHost, isPrivateHost, validateBaseUrl, validateBranch, validateNewPassword, validateRepoUrl, validateSubdirectory, validateUsername } from '~/utils/validators'

describe('hosts that are refused whatever the operator setting is', () => {
  const blocked = [
    ['cloud metadata', '169.254.169.254'], ['AWS service', '169.254.169.253'], ['ECS metadata', '169.254.170.2'], ['Alibaba metadata', '100.100.100.200'],
    ['AWS IPv6 metadata', 'fd00:ec2::254'], ['metadata name', 'metadata.google.internal'],
    ['unspecified', '0.0.0.0'], ['unspecified v6', '::'], ['multicast', '224.0.0.1'], ['reserved', '240.0.0.1'],
    ['v4-mapped metadata', '::ffff:169.254.169.254'],
  ]
  it.each(blocked)('%s', (_label, host) => expect(isAlwaysBlockedHost(host)).toBe(true))

  // Private networks are allowed or refused by the operator setting; only the server knows which.
  const leftToTheServer = ['127.0.0.1', 'localhost', '10.0.0.5', '172.16.12.64', '172.31.255.1', '192.168.1.1', '100.64.0.1', 'fd12:3456::1', '[::1]', 'git.corp.internal', '169.254.10.20', 'fe80::1']
  it.each(leftToTheServer)('%s is not decided in the browser', host => expect(isAlwaysBlockedHost(host)).toBe(false))

  const allowed = ['example.com', 'git.example.com', '8.8.8.8', '172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1', '2606:4700::1111', '192.169.0.1']
  it.each(allowed)('%s is public', host => expect(isAlwaysBlockedHost(host)).toBe(false))

  it('keeps isPrivateHost for the full list of private ranges', () => {
    for (const host of ['127.0.0.1', '10.0.0.5', '172.16.12.64', '192.168.0.9', '100.64.1.1', 'fd00::1', 'localhost']) expect(isPrivateHost(host)).toBe(true)
    expect(isPrivateHost('8.8.8.8')).toBe(false)
  })

  it('rejects always-blocked hosts in repo URLs and base URLs with the friendly message', () => {
    for (const host of ['169.254.169.254', '169.254.170.2', '100.100.100.200', '0.0.0.0', 'metadata.google.internal']) {
      expect(validateRepoUrl(`https://${host}/team/app.git`)).toBe(PRIVATE_NETWORK_MESSAGE)
      expect(validateBaseUrl(`https://${host}:8443/app`)).toBe(PRIVATE_NETWORK_MESSAGE)
    }
    expect(validateRepoUrl('https://[fd00:ec2::254]/team/app.git')).toBe(PRIVATE_NETWORK_MESSAGE)
    expect(validateRepoUrl('git@169.254.169.254:team/app.git')).toBe(PRIVATE_NETWORK_MESSAGE)
    expect(validateRepoUrl('ssh://169.254.170.9/team/app.git')).toBe(PRIVATE_NETWORK_MESSAGE)
    expect(validateRepoUrl('https://[::ffff:169.254.169.254]/x.git')).toBe(PRIVATE_NETWORK_MESSAGE)
  })

  it('lets private-network hosts through so the server can apply the operator setting', () => {
    for (const host of ['172.16.12.64', '10.0.0.5', '192.168.0.9', '127.0.0.1', 'localhost', '100.64.1.1']) {
      expect(validateBaseUrl(`http://${host}:3000`)).toBeNull()
      expect(validateRepoUrl(`https://${host}/team/app.git`)).toBeNull()
    }
    expect(validateRepoUrl('git@10.0.0.7:team/app.git')).toBeNull()
    expect(validateBaseUrl('http://172.16.12.64:3000')).toBeNull()
  })
})

describe('form validators', () => {
  it('accepts the three repository URL forms and rejects the rest', () => {
    expect(validateRepoUrl('https://git.example.com/team/app.git')).toBeNull()
    expect(validateRepoUrl('ssh://git.example.com/team/app.git')).toBeNull()
    expect(validateRepoUrl('git@git.example.com:team/app.git')).toBeNull()
    for (const bad of ['http://git.example.com/a.git', 'git://git.example.com/a.git', 'file:///etc/passwd', 'ext::sh -c id', '/srv/repo', '-oProxyCommand=x', 'https://user:pw@git.example.com/a.git', '']) {
      expect(validateRepoUrl(bad), bad).not.toBeNull()
    }
  })

  it('validates base URLs (no userinfo, no query)', () => {
    expect(validateBaseUrl('https://shop.example.com')).toBeNull()
    expect(validateBaseUrl('http://shop.example.com:8080/app')).toBeNull()
    expect(validateBaseUrl('ftp://shop.example.com')).not.toBeNull()
    expect(validateBaseUrl('https://u:p@shop.example.com')).not.toBeNull()
    expect(validateBaseUrl('https://shop.example.com/?a=1')).not.toBeNull()
    expect(validateBaseUrl('not a url')).not.toBeNull()
  })

  it('validates branch, subdirectory, username and password', () => {
    expect(validateBranch('feature/x-1.2')).toBeNull()
    expect(validateBranch('-bad')).not.toBeNull()
    expect(validateBranch('a b')).not.toBeNull()
    expect(validateSubdirectory('apps/storefront')).toBeNull()
    expect(validateSubdirectory('')).toBeNull()
    expect(validateSubdirectory('/abs')).not.toBeNull()
    expect(validateSubdirectory('a/../b')).not.toBeNull()
    expect(validateUsername('ok.name-1')).toBeNull()
    expect(validateUsername('ab')).not.toBeNull()
    expect(validateNewPassword('short')).not.toBeNull()
    expect(validateNewPassword('a-long-enough-password')).toBeNull()
    expect(validateNewPassword('SameAsUsername1', 'sameasusername1')).not.toBeNull()
  })
})
