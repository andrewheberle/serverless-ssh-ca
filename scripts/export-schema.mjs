import { spawn } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { cwd } from 'node:process'

const SCHEMA_URL = 'http://localhost:8787/openapi.json'
const TIMEOUT_MS = 30_000
const POLL_INTERVAL_MS = 500
const OUTPUT_PATH = join(cwd(), 'openapi.json')

function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms))
}

async function waitForSchema(timeoutMs) {
	const deadline = Date.now() + timeoutMs
	while (Date.now() < deadline) {
		try {
			const res = await fetch(SCHEMA_URL)
			if (res.ok) {
				return await res.text()
			}
		} catch {
			// not ready yet
		}
		await sleep(POLL_INTERVAL_MS)
	}
	return null
}

const wrangler = spawn('npm', ['run', 'dev'], {
	stdio: 'inherit',
})

wrangler.on('error', (err) => {
	process.stderr.write(`failed to start wrangler: ${err.message}\n`)
	process.exit(1)
})

const schema = await waitForSchema(TIMEOUT_MS)

wrangler.kill()

if (!schema) {
	process.stderr.write(`timed out waiting for wrangler dev to be ready after ${TIMEOUT_MS / 1000}s\n`)
	process.exit(1)
}

writeFileSync(OUTPUT_PATH, schema)
process.stdout.write(`schema written to ${OUTPUT_PATH}\n`)
