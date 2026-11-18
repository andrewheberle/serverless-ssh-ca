import { afterAll, afterEach, beforeAll, describe, it, expect, vi } from "vitest"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// When the IdP's JWKS cannot be fetched or used, the CA cannot tell whether a
// token is valid, which is not the requester's fault, so the request is
// answered with a 500 rather than reported as an invalid token (#601)

const claims = { sub: "user123", email: "user@example.com" }
const userKey = ecdsaKey.user()

// a stand-in IdP whose JWKS answers in ways that make it unusable
let server: Server
let base = ""
beforeAll(async () => {
	server = createServer((req, res) => {
		switch (req.url) {
			case "/not-found":
				res.writeHead(404).end("not found")
				break
			case "/not-json":
				res.writeHead(200, { "Content-Type": "application/json" }).end("{not json")
				break
			case "/not-a-jwks":
				res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ hello: "world" }))
				break
			case "/no-keys":
				// a valid JWKS without the key the tokens are signed with
				res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ keys: [] }))
				break
			default:
				res.writeHead(500).end()
		}
	})
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
	base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})
afterAll(async () => {
	await new Promise((resolve) => server.close(resolve))
})
afterEach(() => {
	vi.restoreAllMocks()
})

const issue = async (jwksUrl: string): Promise<Response> => {
	const ca = createSshCa(makeEnv({
		DB: fromNodeSqlite(new DatabaseSync(":memory:")),
		PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
		JWT_JWKS_URL: jwksUrl,
		LOG_LEVEL: "error",
	}))

	return await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await getAccessToken(claims),
			"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
		},
		body: JSON.stringify({ public_key: Buffer.from(userKey.publicKey).toString("base64"), identity: await getIdentityToken(claims) }),
	}))
}

describe("a JWKS that cannot be used", () => {
	it.each([
		["refuses connections", () => "http://127.0.0.1:1/jwks"],
		["answers 404", () => `${base}/not-found`],
		["is not JSON", () => `${base}/not-json`],
		["is not a JWKS", () => `${base}/not-a-jwks`],
	])("should answer with a 500 and log why when the JWKS %s", async (_name, url) => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		const response = await issue(url())

		expect(response.status).toBe(500)
		expect(await response.json()).toEqual({ success: false, errors: [{ code: 7009, message: "Internal Error" }], result: null })
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: expect.stringContaining("JWKS could not be used") }))
	})

	it("should still report a token signed with a key the JWKS does not have as invalid", async () => {
		vi.spyOn(console, "log").mockImplementation(() => undefined)

		const response = await issue(`${base}/no-keys`)

		expect(response.status).toBe(400)
		expect(await response.json()).toMatchObject({ errors: expect.arrayContaining([expect.objectContaining({ path: ["headers", "Authorization"] })]) })
	})
})
