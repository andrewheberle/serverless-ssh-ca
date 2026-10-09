import { spawn, type ChildProcess } from "node:child_process"
import { existsSync, readFileSync, rmSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { afterEach, describe, expect, it } from "vitest"
import { bindings, writeConfig, type TestFiles } from "../tests/helpers.js"

const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url))

type Run = {
	child: ChildProcess
	output: () => string
	exited: Promise<number | null>
}

const run = (...args: string[]): Run => {
	const child = spawn(process.execPath, [cli, ...args], { stdio: ["pipe", "pipe", "pipe"] })
	let output = ""
	child.stdout?.on("data", (chunk: Buffer) => { output += chunk.toString() })
	child.stderr?.on("data", (chunk: Buffer) => { output += chunk.toString() })

	return {
		child,
		output: () => output,
		exited: new Promise(resolve => child.on("exit", code => resolve(code))),
	}
}

const waitForPort = async (r: Run, portFile: string): Promise<number> => {
	const deadline = Date.now() + 90_000
	while (Date.now() < deadline) {
		if (r.child.exitCode !== null) {
			throw new Error(`exited with ${r.child.exitCode}:\n${r.output()}`)
		}
		if (existsSync(portFile)) {
			const port = readFileSync(portFile, "utf-8")
			if (port !== "") {
				return Number(port)
			}
		}
		await new Promise(resolve => setTimeout(resolve, 50))
	}
	throw new Error(`timed out waiting for port:\n${r.output()}`)
}

describe.each(["node", "workerd"])("serverless-ssh-ca-test-server --runtime %s", (runtime) => {
	let files: TestFiles | undefined
	let current: Run | undefined

	afterEach(() => {
		current?.child.kill()
		current = undefined
		if (files !== undefined) {
			rmSync(files.dir, { recursive: true, force: true })
			files = undefined
		}
	})

	it("should serve the CA, log requests and exit when stdin closes", async () => {
		files = writeConfig()
		current = run("--runtime", runtime, files.configFile)

		const port = await waitForPort(current, files.portFile)

		const ok = await fetch(`http://127.0.0.1:${port}/api/v3/ca`)
		expect(ok.status).toBe(200)
		expect(await ok.text()).toContain("ssh-ed25519")

		const rejected = await fetch(`http://127.0.0.1:${port}/api/v3/user/certificate`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: "{}",
		})
		expect(rejected.status).toBeGreaterThanOrEqual(400)
		const body = await rejected.text()

		current.child.stdin?.end()
		expect(await current.exited).toBe(0)

		const lines = readFileSync(files.logFile, "utf-8").trim().split("\n").flatMap(l => {
			try {
				return [JSON.parse(l)]
			} catch {
				return []
			}
		})
		expect(lines).toContainEqual({ level: "info", message: "harness request", method: "GET", url: "/api/v3/ca", status: 200 })
		expect(lines).toContainEqual({ level: "info", message: "harness request", method: "POST", url: "/api/v3/user/certificate", status: rejected.status, body })
		expect(lines.filter(l => l.level === "error" && String(l.message).startsWith("harness"))).toEqual([])
	})
})

describe("serverless-ssh-ca-test-server", () => {
	let files: TestFiles | undefined

	afterEach(() => {
		if (files !== undefined) {
			rmSync(files.dir, { recursive: true, force: true })
			files = undefined
		}
	})

	it("should exit with an error for an unknown runtime", async () => {
		files = writeConfig()
		const r = run("--runtime", "bun", files.configFile)

		expect(await r.exited).toBe(1)
		expect(r.output()).toContain("usage:")
	})

	it("should exit with an error without a configuration file", async () => {
		const r = run()

		expect(await r.exited).toBe(1)
		expect(r.output()).toContain("usage:")
	})

	it("should exit with an error for an invalid CA configuration", async () => {
		files = writeConfig({ bindings: { ...bindings, SSH_CERTIFICATE_LIFETIME: "forever" } })
		const r = run(files.configFile)

		expect(await r.exited).toBe(1)
		expect(r.output()).toContain("SSH_CERTIFICATE_LIFETIME")
		expect(existsSync(files.portFile)).toBe(false)
	})
})
