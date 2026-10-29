/** Example CI command shown next to a newly created ingest token. The token itself is a placeholder in the sample. */
export function ingestCurlExample(origin: string): string {
  return [
    'curl --fail-with-body --silent --show-error --retry 3 \\',
    `  -X POST "${origin}/api/v1/ingest?project=<PROJECT NAME>&codebase=<CODEBASE NAME>&ref=$GIT_COMMIT" \\`,
    '  -H "Authorization: Bearer $SDRSCAN_TOKEN" \\',
    '  -H "Content-Type: application/json" \\',
    '  --data-binary @sdrscan.sarif',
  ].join('\n')
}
