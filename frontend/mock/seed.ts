// Seed data for the development mock backend (never shipped in the production build).
// Includes hostile strings (HTML in paths, messages and snippets) on purpose: the UI must render them as text.
import type { Severity, Vulnerability } from '../types/api'

export interface FindingTemplate {
  key: string
  rule_id: string
  severity: Severity
  confidence?: 'normal' | 'low'
  message: string
  path?: string
  url?: string
  start_line?: number | null
  end_line?: number | null
  start_column?: number | null
  end_column?: number | null
  snippet: string
  redacted?: boolean
  cwe: string[]
  /** Vulnerability findings (SCA / DAST CVE) carry this object; code findings do not. */
  vulnerability?: Vulnerability
}

const RULES: Array<{ rule_id: string, severity: Severity, cwe: string[], message: string, snippet: string }> = [
  { rule_id: 'php-sql-injection', severity: 'critical', cwe: ['CWE-89'], message: 'User input is concatenated into an SQL query. Use prepared statements.', snippet: '$db->query("SELECT * FROM orders WHERE id = " . $_GET[\'id\']);' },
  { rule_id: 'php-eval-use', severity: 'critical', cwe: ['CWE-95'], message: 'eval() executes dynamic code; remove it or whitelist the input.', snippet: 'eval($payload);' },
  { rule_id: 'php-unserialize', severity: 'high', cwe: ['CWE-502'], message: 'unserialize() on untrusted data can lead to object injection.', snippet: '$cart = unserialize($_COOKIE[\'cart\']);' },
  { rule_id: 'php-file-inclusion', severity: 'high', cwe: ['CWE-98'], message: 'File path built from user input is passed to include.', snippet: 'include $_GET[\'page\'] . \'.php\';' },
  { rule_id: 'php-command-injection', severity: 'high', cwe: ['CWE-78'], message: 'User input reaches a shell command.', snippet: 'system("convert " . $_POST[\'file\']);' },
  { rule_id: 'php-xss-echo', severity: 'medium', cwe: ['CWE-79'], message: 'Unescaped user input is echoed into HTML. Use htmlspecialchars().', snippet: 'echo "<p>" . $_GET[\'q\'] . "</p>";' },
  { rule_id: 'php-weak-hash-md5', severity: 'medium', cwe: ['CWE-328'], message: 'MD5 is not suitable for password hashing. Use password_hash().', snippet: '$hash = md5($password);' },
  { rule_id: 'php-open-redirect', severity: 'medium', cwe: ['CWE-601'], message: 'Redirect target comes from user input.', snippet: 'header("Location: " . $_GET[\'next\']);' },
  { rule_id: 'php-csrf-missing', severity: 'medium', cwe: ['CWE-352'], message: 'State-changing handler has no CSRF token check.', snippet: 'if ($_SERVER[\'REQUEST_METHOD\'] === \'POST\') {' },
  { rule_id: 'php-insecure-cookie', severity: 'low', cwe: ['CWE-614'], message: 'Cookie is set without the Secure flag.', snippet: 'setcookie(\'sid\', $id);' },
  { rule_id: 'php-error-display', severity: 'low', cwe: ['CWE-209'], message: 'display_errors is enabled; errors can leak internals.', snippet: 'ini_set(\'display_errors\', 1);' },
  { rule_id: 'php-debug-output', severity: 'info', cwe: ['CWE-215'], message: 'Debug output left in code.', snippet: 'var_dump($order);' },
]

const STOREFRONT_PATHS = [
  'src/Controller/CartController.php', 'src/Controller/OrderController.php', 'src/Auth/Login.php', 'src/Util/Hash.php',
  'src/Service/PaymentService.php', 'src/Service/Mailer.php', 'public/index.php', 'public/checkout.php', 'src/View/helpers.php',
  'src/Repository/ProductRepository.php', 'src/Repository/UserRepository.php', 'src/Util/Redirect.php',
]

const API_PATHS = ['app/Http/AuthController.php', 'app/Http/UserController.php', 'app/Models/User.php', 'app/Support/Crypto.php', 'routes/api.php', 'app/Http/ReportController.php']
const BILLING_PATHS = ['src/Invoice/InvoiceController.php', 'src/Invoice/Pdf.php', 'src/Payments/Gateway.php', 'src/Util/Debug.php']

function mulberry(seed: number) {
  let a = seed
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function generate(prefix: string, paths: string[], count: number, seed: number): FindingTemplate[] {
  const rnd = mulberry(seed)
  const out: FindingTemplate[] = []
  for (let i = 0; i < count; i++) {
    const rule = RULES[Math.floor(rnd() * RULES.length)]!
    const path = paths[Math.floor(rnd() * paths.length)]!
    const line = 5 + Math.floor(rnd() * 180)
    out.push({
      key: `${prefix}:${i}`,
      rule_id: rule.rule_id,
      severity: rule.severity,
      confidence: rnd() < 0.08 ? 'low' : 'normal',
      message: rule.message,
      path,
      start_line: line,
      end_line: line,
      start_column: 3 + Math.floor(rnd() * 8),
      end_column: 60,
      snippet: rule.snippet,
      cwe: rule.cwe,
    })
  }
  return out
}

/** Hand written findings that exercise special rendering paths. */
const SPECIAL: FindingTemplate[] = [
  {
    key: 'sf:secret', rule_id: 'php-hardcoded-secret', severity: 'high', message: 'Hard-coded secret or credential in code; move it to configuration or a secret manager.',
    path: 'src/Config.php', start_line: 12, end_line: 12, start_column: 5, end_column: 48, snippet: "$apiKey = '[REDACTED]'", redacted: true, cwe: ['CWE-798'],
  },
  {
    key: 'sf:multiline', rule_id: 'php-sql-injection', severity: 'critical', message: 'Query is assembled from request data across several statements.',
    path: 'src/Repository/OrderRepository.php', start_line: 40, end_line: 43, start_column: 9, end_column: 30,
    snippet: '$sql = "SELECT * FROM orders";\n$sql .= " WHERE customer = \'" . $_POST[\'c\'] . "\'";\n$sql .= " ORDER BY " . $_GET[\'sort\'];\n$rows = $db->query($sql);', cwe: ['CWE-89'],
  },
  {
    key: 'sf:xss-payload', rule_id: 'php-xss-echo', severity: 'medium',
    message: '<script>alert("xss-in-message")</script> reflected parameter is echoed unescaped.',
    path: 'src/View/<img src=x onerror=alert(1)>.php', start_line: 7, end_line: 7, start_column: 1, end_column: 60,
    snippet: 'echo "<b onmouseover=alert(1)>" . $_GET[\'name\'] . "</b>";', cwe: ['CWE-79', 'CWE-javascript:alert(1)'],
  },
  {
    key: 'sf:noline', rule_id: 'php-config-exposed', severity: 'low', message: 'Configuration file is web-accessible.',
    path: '.env.example', start_line: null, end_line: null, snippet: '', cwe: ['CWE-538'],
  },
  {
    key: 'sf:lowconf', rule_id: 'php-possible-ssrf', severity: 'medium', confidence: 'low', message: 'URL fetch may use user input (low confidence).',
    path: 'src/Service/Mailer.php', start_line: 88, end_line: 88, start_column: 5, end_column: 50, snippet: '$body = file_get_contents($url);', cwe: ['CWE-918'],
  },
  {
    key: 'sf:partial-new', rule_id: 'php-xss-echo', severity: 'medium', message: 'Unescaped user input is echoed into HTML. Use htmlspecialchars().',
    path: 'src/Controller/CartController.php', start_line: 201, end_line: 201, start_column: 5, end_column: 55, snippet: 'echo "<li>" . $_GET[\'coupon\'] . "</li>";', cwe: ['CWE-79'],
  },
]

export const STOREFRONT_TEMPLATES: FindingTemplate[] = [...generate('sf', STOREFRONT_PATHS, 44, 7), ...SPECIAL]
export const API_TEMPLATES: FindingTemplate[] = generate('api', API_PATHS, 22, 11)
export const BILLING_TEMPLATES: FindingTemplate[] = generate('bill', BILLING_PATHS, 9, 3).filter(t => t.severity !== 'critical')

export const DAST_TEMPLATES: FindingTemplate[] = [
  {
    key: 'dast:1', rule_id: 'http-cookie-missing-httponly', severity: 'medium', message: 'Session cookie is set without the HttpOnly flag.',
    url: 'https://admin.example.com/login', snippet: 'GET /login HTTP/1.1\n\nHTTP/1.1 200 OK\nSet-Cookie: sid=[REDACTED]; Path=/; Secure', redacted: true, cwe: ['CWE-1004'],
  },
  {
    key: 'dast:2', rule_id: 'http-missing-csp', severity: 'low', message: 'Response has no Content-Security-Policy header.',
    url: 'https://admin.example.com/', snippet: 'GET / HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Type: text/html', cwe: ['CWE-693'],
  },
  {
    key: 'dast:3', rule_id: 'http-server-banner', severity: 'info', message: 'Server header reveals software version.',
    url: 'https://admin.example.com/health', snippet: 'GET /health HTTP/1.1\n\nHTTP/1.1 200 OK\nServer: nginx/1.18.0', cwe: ['CWE-200'],
  },
  {
    key: 'dast:4', rule_id: 'http-missing-hsts', severity: 'low', message: 'Strict-Transport-Security header is missing.',
    url: 'https://admin.example.com/login', snippet: 'GET /login HTTP/1.1\n\nHTTP/1.1 200 OK', cwe: ['CWE-319'],
  },
]

/** SCA findings (lockfile locations) with hostile strings in names, versions, ids and references on purpose. */
export const SCA_TEMPLATES: FindingTemplate[] = [
  {
    key: 'sca:symfony', rule_id: 'CVE-2023-46734', severity: 'high', message: 'symfony/twig-bridge 5.4.30 is affected by CVE-2023-46734 (XSS in the Twig extensions).',
    path: 'composer.lock', start_line: 1204, end_line: 1204, start_column: 1, end_column: 40, snippet: '"name": "symfony/twig-bridge", "version": "v5.4.30"', cwe: ['CWE-79'],
    vulnerability: {
      ids: ['CVE-2023-46734', 'GHSA-q847-2q57-wmr3', 'PKSA-2099-FRAM-0001'], package: { ecosystem: 'Packagist', name: 'symfony/twig-bridge', version: '5.4.30' }, fixed_versions: ['5.4.31', '6.3.8'],
      source: 'osv', cvss: { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }, confidence: 'high', scope: 'runtime',
      references: [
        'https://symfony.com/cve-2023-46734', 'https://github.com/advisories/GHSA-q847-2q57-wmr3', 'javascript:alert(document.cookie)',
        'ftp://files.example.com/advisory.txt', 'https://user:secret@evil.example.com/steal',
      ],
    },
  },
  {
    key: 'sca:lodash', rule_id: 'CVE-2021-23337', severity: 'high', message: 'lodash 4.17.15 is affected by CVE-2021-23337 (command injection in template).',
    path: 'package-lock.json', start_line: 5120, end_line: 5120, start_column: 1, end_column: 30, snippet: '"lodash": { "version": "4.17.15" }', cwe: ['CWE-94'],
    vulnerability: {
      ids: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm', 'GHSA-2099-fram-0001'], package: { ecosystem: 'npm', name: 'lodash', version: '4.17.15' }, fixed_versions: ['4.17.21'],
      source: 'osv', cvss: { score: 7.2, vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }, confidence: 'high', scope: 'runtime',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
    },
  },
  {
    key: 'sca:xss', rule_id: 'CVE-2024-99999', severity: 'medium', message: '<script>alert("xss-in-message")</script> vulnerable dependency (development only).',
    path: 'package-lock.json', start_line: 8801, end_line: 8801, start_column: 1, end_column: 30, snippet: '"name": "<img src=x onerror=alert(1)>"', cwe: [],
    vulnerability: {
      ids: ['CVE-2024-99999', 'GHSA-<b>bad</b>', 'cve-2024-1'], package: { ecosystem: 'npm', name: '<img src=x onerror=alert(1)>/pkg', version: '1.0.0"><script>alert(2)</script>' },
      fixed_versions: ['<b>2.0</b>'], source: 'osv', cvss: null, confidence: 'high', scope: 'dev', references: ['http://example.com/<b>x</b>'],
    },
  },
]

/** Active (payload-sending) DAST findings: rule ids the real engine prefixes with "dast-active-". */
export const DAST_ACTIVE_TEMPLATES: FindingTemplate[] = [
  {
    key: 'dastactive:sqli', rule_id: 'dast-active-sqli-error-based', severity: 'critical',
    message: 'A database error was disclosed after injecting a test payload into the "id" parameter.',
    url: "https://admin.example.com/report?id=1'", snippet: "GET /report?id=1' HTTP/1.1\n\nHTTP/1.1 500 Internal Server Error\nSQL syntax error near '''", cwe: ['CWE-89'],
  },
  {
    key: 'dastactive:xss', rule_id: 'dast-active-xss-reflected', severity: 'high',
    message: 'A test script payload sent in the "q" parameter was reflected unescaped in the response.',
    url: 'https://admin.example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', snippet: 'GET /search?q=<script>alert(1)</script> HTTP/1.1\n\nHTTP/1.1 200 OK\n...<script>alert(1)</script>...', cwe: ['CWE-79'],
  },
  {
    key: 'dastactive:redirect', rule_id: 'dast-active-open-redirect-confirmed', severity: 'medium',
    message: 'The "next" parameter redirected to an attacker-controlled test URL.',
    url: 'https://admin.example.com/login?next=https://evil.example.net', snippet: 'GET /login?next=https://evil.example.net HTTP/1.1\n\nHTTP/1.1 302 Found\nLocation: https://evil.example.net', cwe: ['CWE-601'],
  },
  {
    key: 'dastactive:header', rule_id: 'dast-active-header-injection', severity: 'medium',
    message: 'A CRLF test payload in a request header was reflected into the response headers.',
    url: 'https://admin.example.com/set-lang?lang=en%0d%0aX-Injected:1', snippet: 'GET /set-lang?lang=en%0d%0aX-Injected:1 HTTP/1.1\n\nHTTP/1.1 200 OK\nX-Injected:1', cwe: ['CWE-113'],
  },
]

/** DAST: a product version matched against CVE data (low confidence: the vendor may have patched without a version bump). */
export const DAST_VULN_TEMPLATES: FindingTemplate[] = [
  {
    key: 'dastvuln:nginx', rule_id: 'CVE-2021-23017', severity: 'high', message: 'nginx 1.18.0 is affected by CVE-2021-23017 (off-by-one in the resolver).',
    url: 'https://status.example.com/', snippet: 'GET / HTTP/1.1\n\nHTTP/1.1 200 OK\nServer: nginx/1.18.0', cwe: ['CWE-193'],
    vulnerability: {
      ids: ['CVE-2021-23017'], package: { product: 'cpe:2.3:a:nginx:nginx', version: '1.18.0' }, fixed_versions: ['1.20.1', '1.21.0'], source: 'nvd',
      cvss: { score: 7.7, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H' }, confidence: 'low', scope: null,
      references: ['https://nginx.org/en/security_advisories.html', 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'],
    },
  },
  {
    key: 'dastvuln:csp', rule_id: 'http-missing-csp', severity: 'low', message: 'Response has no Content-Security-Policy header.',
    url: 'https://status.example.com/', snippet: 'GET / HTTP/1.1\n\nHTTP/1.1 200 OK', cwe: ['CWE-693'],
  },
]

export function fingerprintOf(key: string): string {
  let h1 = 0xdeadbeef
  let h2 = 0x41c6ce57
  const parts: string[] = []
  for (let round = 0; round < 8; round++) {
    for (let i = 0; i < key.length; i++) {
      const c = key.charCodeAt(i) + round
      h1 = Math.imul(h1 ^ c, 2654435761)
      h2 = Math.imul(h2 ^ c, 1597334677)
    }
    parts.push(((h1 ^ h2) >>> 0).toString(16).padStart(8, '0'))
  }
  return parts.join('')
}
