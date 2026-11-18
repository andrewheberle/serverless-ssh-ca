import { describe, it, expect } from "vitest"
import { createHash } from "node:crypto"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { inlineScriptHashes } from "../src/web/docs.js"
import { makeEnv } from "./env.js"
import { key as ed25519Key } from "./keys/ed25519.js"

// The API docs share an origin with the admin UI, so they are served with a
// Content-Security-Policy, and only the documented ones are served (#611)

const get = async (path: string): Promise<Response> => await createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
})).fetch(new Request(`http://example.com${path}`))

// the directives of a Content-Security-Policy, by name
const directives = (policy: string | null): Map<string, string[]> => new Map((policy ?? "").split(";").map((d) => d.trim().split(/\s+/)).map(([name = "", ...values]) => [name, values]))

describe("API docs", () => {
	it.each(["/redocs", "/openapi.yaml"])("should not serve %s", async (path) => {
		expect((await get(path)).status).toBe(404)
	})

	it("should serve the schema as JSON with nosniff", async () => {
		const response = await get("/openapi.json")

		expect(response.status).toBe(200)
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff")
		expect(await response.json()).toMatchObject({ openapi: expect.any(String) })
	})

	it("should serve /docs with the CA's security headers", async () => {
		const response = await get("/docs")

		expect(response.status).toBe(200)
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff")
		expect(response.headers.get("Referrer-Policy")).toBe("same-origin")
		expect(response.headers.get("Cache-Control")).toBe("no-store")

		const csp = directives(response.headers.get("Content-Security-Policy"))
		expect(csp.get("default-src")).toEqual(["'none'"])
		expect(csp.get("style-src")).toEqual(["https://cdn.jsdelivr.net"])
		expect(csp.get("connect-src")).toEqual(["'self'"])
		expect(csp.get("frame-ancestors")).toEqual(["'none'"])
		expect(csp.get("base-uri")).toEqual(["'none'"])
	})

	it("should allow exactly the inline scripts /docs serves", async () => {
		const response = await get("/docs")
		const html = await response.text()

		// hashed here independently of the CA, from the scripts chanfana serves
		const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(([, body = ""]) => `'sha256-${createHash("sha256").update(body).digest("base64")}'`)
		expect(inline).toHaveLength(1)

		const scriptSrc = directives(response.headers.get("Content-Security-Policy")).get("script-src")
		expect(scriptSrc).toEqual(["https://cdn.jsdelivr.net", ...inline])
	})

	it("should load every script and stylesheet /docs uses from an allowed origin", async () => {
		const html = await (await get("/docs")).text()

		const urls = [...html.matchAll(/<(?:script|link)[^>]+(?:src|href)="(https?:[^"]+)"/g)].map(([, url = ""]) => new URL(url).origin)
		expect(urls.length).toBeGreaterThan(0)
		expect(new Set(urls)).toEqual(new Set(["https://cdn.jsdelivr.net"]))
	})
})

describe("inlineScriptHashes", () => {
	it("should hash inline scripts and skip scripts loaded from a URL", async () => {
		const html = `<script src="https://example.com/a.js"></script><script>alert(1)</script><script type="module">b()</script>`

		expect(await inlineScriptHashes(html)).toEqual([
			`'sha256-${createHash("sha256").update("alert(1)").digest("base64")}'`,
			`'sha256-${createHash("sha256").update("b()").digest("base64")}'`,
		])
	})
})
