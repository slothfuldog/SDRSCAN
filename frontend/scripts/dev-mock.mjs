// Starts the mock API and `nuxt dev` together; Nuxt proxies /api to the mock.
import { spawn } from 'node:child_process'

const port = process.env.MOCK_PORT || '8787'
const env = { ...process.env, MOCK_PORT: port, SDRSCAN_API_URL: `http://127.0.0.1:${port}` }
const procs = [
  spawn(process.execPath, ['mock/server.ts'], { stdio: 'inherit', env }),
  spawn('npx', ['nuxt', 'dev', ...process.argv.slice(2)], { stdio: 'inherit', env }),
]
const stop = () => procs.forEach(p => p.kill('SIGTERM'))
process.on('SIGINT', stop)
process.on('SIGTERM', stop)
procs.forEach(p => p.on('exit', () => { stop(); process.exit(0) }))
