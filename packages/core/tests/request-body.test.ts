import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { MaxRequestBodySize } from "../src/api/body.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// Request bodies are limited in size and must be JSON when they are sent (#607)

const claims = { sub: "user123", email: "user@example.com" }
const userKey = ecdsaKey.user()
const path = "/api/v4/user/certificates"

const newCa = (): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
}))

// a user certificate request with a valid body, which may be replaced
const issue = async (body: (valid: Record<string, unknown>) => BodyInit, contentType = "application/json"): Promise<Response> => {
	const valid = { public_key: Buffer.from(userKey.publicKey).toString("base64"), identity: await getIdentityToken(claims) }

	return await newCa().fetch(new Request(`http://example.com${path}`, {
		method: "POST",
		headers: {
			"Content-Type": contentType,
			"Authorization": await getAccessToken(claims),
			"Proof-Of-Possession": generateRequestProof(userKey, "POST", path),
		},
		body: body(valid),
	}))
}

describe("request bodies", () => {
	it("should refuse a body larger than the limit with a 413 before verifying any token", async () => {
		const response = await newCa().fetch(new Request(`http://example.com${path}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ padding: "x".repeat(MaxRequestBodySize) }),
		}))

		expect(response.status).toBe(413)
		expect(await response.json()).toEqual({ success: false, errors: [{ code: 413, message: "request body is too large" }], result: null })
	})

	it("should refuse a body larger than the limit sent without a Content-Length", async () => {
		const chunk = new TextEncoder().encode("x".repeat(16 * 1024))
		let sent = 0
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) {
				if (sent > MaxRequestBodySize) {
					controller.close()
					return
				}
				sent += chunk.length
				controller.enqueue(chunk)
			},
		})

		const response = await newCa().fetch(new Request(`http://example.com${path}`, { method: "POST", body: stream, duplex: "half" } as RequestInit))

		expect(response.status).toBe(413)
	})

	it.each(["{not json", "{\"public_key\":", "<xml/>"])("should refuse a body of %j that is not JSON with a 400 saying so", async (text) => {
		const response = await issue(() => text)

		expect(response.status).toBe(400)
		expect(await response.json()).toEqual({ success: false, errors: [{ code: 7001, message: "request body is not valid JSON", path: ["body"] }], result: null })
	})

	it("should issue a certificate for a valid body", async () => {
		expect((await issue((valid) => JSON.stringify(valid))).status).toBe(200)
	})

	it("should issue a certificate for a valid JSON body sent as text/plain", async () => {
		expect((await issue((valid) => JSON.stringify(valid), "text/plain")).status).toBe(200)
	})

	it("should ignore fields the request does not have", async () => {
		expect((await issue((valid) => JSON.stringify({ ...valid, unknown: "field" }))).status).toBe(200)
	})

	it("should leave an empty body to the route, which reports the missing fields", async () => {
		const response = await issue(() => "")

		expect(response.status).toBe(400)
		expect(await response.json()).toMatchObject({ errors: expect.arrayContaining([expect.objectContaining({ path: ["body", "public_key"] })]) })
	})
})
