import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// The responses to requests whose tokens are not accepted are relied on by the
// client and its end-to-end tests, so their status and body are pinned here for
// every endpoint that issues a certificate.

const email = "user@example.com"
const sub = "user123"
const userKey = ecdsaKey.user()
const hostKey = ecdsaKey.host()
const publicKey = (key: { publicKey: string }): string => Buffer.from(key.publicKey).toString("base64")

const newCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
	...overrides,
}))

type Tokens = { authorization: string, identity: string }

type Endpoint = {
	name: string
	host: boolean
	request: (ca: SshCa, tokens: Tokens) => Promise<Response>
}

const endpoints: Endpoint[] = [
	{
		name: "POST /api/v3/user/certificate",
		host: false,
		request: async (ca, { authorization, identity }) => await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
			method: "POST",
			headers: { "Content-Type": "application/json", "Authorization": authorization },
			body: JSON.stringify({ public_key: publicKey(userKey), proof: generateProof(userKey), identity }),
		})),
	},
	{
		name: "POST /api/v3/host/certificate",
		host: true,
		request: async (ca, { authorization, identity }) => await ca.fetch(new Request("http://example.com/api/v3/host/certificate", {
			method: "POST",
			headers: { "Content-Type": "application/json", "Authorization": authorization },
			body: JSON.stringify({ public_key: publicKey(hostKey), proof: generateProof(hostKey), identity, principals: ["test_host"] }),
		})),
	},
	{
		name: "POST /api/v4/user/certificates",
		host: false,
		request: async (ca, { authorization, identity }) => await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": authorization,
				"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
			},
			body: JSON.stringify({ public_key: publicKey(userKey), identity }),
		})),
	},
	{
		name: "POST /api/v4/host/certificates",
		host: true,
		request: async (ca, { authorization, identity }) => await ca.fetch(new Request("http://example.com/api/v4/host/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": authorization,
				"Proof-Of-Possession": generateRequestProof(hostKey, "POST", "/api/v4/host/certificates"),
			},
			body: JSON.stringify({ public_key: publicKey(hostKey), identity, principals: ["test_host"] }),
		})),
	},
]

const validTokens = async (): Promise<Tokens> => ({
	authorization: await getAccessToken({ sub, email }),
	identity: await getIdentityToken({ sub, email }),
})

const validationError = (...errors: { message: string, path: string[] }[]) => ({
	success: false,
	errors: errors.map((error) => ({ code: 7001, ...error })),
	result: {},
})

const accessTokenPath = ["headers", "Authorization"]
const identityTokenPath = ["body", "identity"]

describe.each(endpoints)("responses to tokens that are not accepted ($name)", ({ request, host }) => {
	const ca = newCa()

	it("should issue a certificate for valid tokens", async () => {
		const response = await request(ca, await validTokens())
		expect(response.status).toBe(200)
	})

	it("should return 400 for an Authorization header that is not a Bearer token", async () => {
		const response = await request(ca, { ...await validTokens(), authorization: "Basic foo" })
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(validationError({ message: "authorization header must be a Bearer token", path: accessTokenPath }))
	})

	it("should return 400 for an expired access token", async () => {
		const authorization = await getAccessToken({ sub, email, exp: Math.floor(Date.now() / 1000) - 3600 })
		const response = await request(ca, { ...await validTokens(), authorization })
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(validationError({ message: "the access token has expired", path: accessTokenPath }))
	})

	it("should return 400 for an access token without an email claim", async () => {
		// the test IdP is given the claims as is
		const authorization = await getAccessToken({ sub } as { sub: string, email: string })
		const response = await request(ca, { ...await validTokens(), authorization })
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(validationError({ message: "JWT was verified but was missing required email claim", path: accessTokenPath }))
	})

	it("should return 400 for an identity token that cannot be verified", async () => {
		const response = await request(ca, { ...await validTokens(), identity: "foo" })
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(validationError({ message: "problem parsing identity token", path: identityTokenPath }))
	})

	it("should return 400 listing both tokens when neither can be verified", async () => {
		const response = await request(ca, { authorization: "Bearer foo", identity: "foo" })
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(validationError(
			{ message: "the access token was invalid", path: accessTokenPath },
			{ message: "problem parsing identity token", path: identityTokenPath },
		))
	})

	it("should return 403 when the tokens are for different subjects", async () => {
		const response = await request(ca, { ...await validTokens(), identity: await getIdentityToken({ sub: "user456", email }) })
		expect(response.status).toBe(403)
		expect(await response.json()).toEqual({
			success: false,
			result: {},
			errors: [{ code: 7004, message: `${host ? "possible" : "Possible"} token substitution as subjects for authentication and identity tokens did not match` }],
		})
	})

	it("should return 500 when no audience is configured", async () => {
		const response = await request(newCa({ JWT_AUD: "" }), await validTokens())
		expect(response.status).toBe(500)
		expect(await response.json()).toEqual({
			success: false,
			result: {},
			errors: [{ code: 7009, message: "Internal Error" }],
		})
	})

	it("should return 500 when the userinfo endpoint cannot be reached", async () => {
		const response = await request(newCa({ OIDC_USERINFO_URL: "http://localhost:1/userinfo" }), await validTokens())
		expect(response.status).toBe(500)
		expect(await response.json()).toEqual({
			success: false,
			result: {},
			errors: [{ code: 7009, message: "Internal Error" }],
		})
	})

	it.runIf(host)("should return 401 when the requester may not request host certificates", async () => {
		const response = await request(newCa({ SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: "admin@example.com" }), await validTokens())
		expect(response.status).toBe(401)
		expect(await response.json()).toEqual({
			success: false,
			result: {},
			errors: [{ code: 7003, message: "User not allowed to issue host certificates" }],
		})
	})
})
