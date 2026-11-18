import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// A request under /api/ that matches no route gets the API's JSON error body,
// so a client can tell it from a 404 for a certificate by its message (#606)

const newCa = (): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
}))

const request = async (method: string, path: string, init: RequestInit = {}): Promise<Response> =>
	await newCa().fetch(new Request(`http://example.com${path}`, { method, ...init }))

describe("unknown API routes", () => {
	it.each([
		["GET", "/api/v4/nope"],
		["GET", "/api/v4/user/certificates"],
		["PUT", "/api/v4/user/certificates"],
		["GET", "/api/v4/ca/"],
		["GET", "/api/v4//ca"],
		["OPTIONS", "/api/v4/ca"],
		["DELETE", "/api/v4/user/certificates/"],
		["GET", "/api/v5/ca"],
	])("should answer %s %s with a JSON 404", async (method, path) => {
		const response = await request(method, path)

		expect(response.status).toBe(404)
		expect(response.headers.get("Content-Type")).toMatch(/^application\/json/)
		expect(await response.json()).toEqual({ success: false, errors: [{ code: 7002, message: "not found" }], result: null })
	})

	it("should still say a certificate was not found when revoking one that does not exist", async () => {
		const path = "/api/v4/user/certificates/1234"
		const response = await request("DELETE", path, { headers: { "Proof-Of-Possession": generateRequestProof(ecdsaKey.user(), "DELETE", path) } })

		expect(response.status).toBe(404)
		expect(await response.json()).toMatchObject({ errors: [{ message: "certificate not found" }] })
	})

	it.each(["/nope", "/admin", "/api"])("should keep the plain text 404 for %s", async (path) => {
		const response = await request("GET", path)

		expect(response.status).toBe(404)
		expect(await response.text()).toBe("404 Not Found")
	})

	it("should still answer API v3 with 410", async () => {
		expect((await request("GET", "/api/v3/ca")).status).toBe(410)
	})
})
