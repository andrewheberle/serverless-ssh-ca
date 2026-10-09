import { readFileSync, rmSync } from "node:fs"
import { afterEach, describe, expect, it } from "vitest"
import { startTestServer, type TestServer } from "../src/index.js"
import { bindings, writeConfig, type TestFiles } from "./helpers.js"

describe("startTestServer under node", () => {
	let files: TestFiles | undefined
	let server: TestServer | undefined

	const logLines = (): unknown[] => files === undefined
		? []
		: readFileSync(files.logFile, "utf-8").trim().split("\n").map(l => JSON.parse(l))

	afterEach(async () => {
		await server?.close()
		server = undefined
		if (files !== undefined) {
			rmSync(files.dir, { recursive: true, force: true })
			files = undefined
		}
	})

	it("should write the port and serve the CA", async () => {
		files = writeConfig()
		server = await startTestServer("node", files.configFile)

		expect(readFileSync(files.portFile, "utf-8")).toBe(String(server.port))

		const response = await fetch(`http://127.0.0.1:${server.port}/api/v3/ca`)
		expect(response.status).toBe(200)
		expect(await response.text()).toContain("ssh-ed25519")

		expect(logLines()).toContainEqual({ level: "info", message: "harness request", method: "GET", url: "/api/v3/ca", status: 200 })
	})

	it("should log the body of rejected requests", async () => {
		files = writeConfig()
		server = await startTestServer("node", files.configFile)

		const response = await fetch(`http://127.0.0.1:${server.port}/api/v3/user/certificate`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: "{}",
		})
		expect(response.status).toBeGreaterThanOrEqual(400)

		expect(logLines()).toContainEqual(expect.objectContaining({
			message: "harness request",
			method: "POST",
			url: "/api/v3/user/certificate",
			status: response.status,
			body: await response.text(),
		}))
	})

	it("should send CA console output to the log until closed", async () => {
		const log = console.log
		files = writeConfig()
		server = await startTestServer("node", files.configFile)

		expect(console.log).not.toBe(log)
		console.log({ level: "INFO", message: "from the CA" })
		expect(logLines()).toContainEqual({ level: "INFO", message: "from the CA" })

		await server.close()
		server = undefined
		expect(console.log).toBe(log)
	})

	it("should reject an invalid CA configuration", async () => {
		files = writeConfig({ bindings: { ...bindings, SSH_CERTIFICATE_LIFETIME: "forever" } })

		await expect(startTestServer("node", files.configFile)).rejects.toThrow(/SSH_CERTIFICATE_LIFETIME/)
	})
})
