import { afterEach, describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken, getOpaqueAccessToken } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { listCertificate } from "./helpers/ssh-keygen.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const oidcBase = `http://localhost:${process.env.OIDC_PORT ?? "4567"}`

const sub = "user123"
const claims = { sub, email: "user@example.com" }
const userKey = ecdsaKey.user()
const publicKey = Buffer.from(userKey.publicKey).toString("base64")

const createCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	OIDC_USERINFO_URL: `${oidcBase}/userinfo`,
	...overrides,
}))

type Request = (ca: SshCa, authorization: string) => Promise<Response>

const requests: [string, Request][] = [
	["POST /api/v3/user/certificate", async (ca, authorization) => await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
		method: "POST",
		headers: { "Content-Type": "application/json", "Authorization": authorization },
		body: JSON.stringify({ public_key: publicKey, proof: generateProof(userKey), identity: await getIdentityToken(claims) }),
	}))],
	["POST /api/v4/user/certificates", async (ca, authorization) => await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": authorization,
			"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
		},
		body: JSON.stringify({ public_key: publicKey, identity: await getIdentityToken(claims) }),
	}))],
]

const errorMessages = async (response: Response): Promise<string[]> => {
	const body = await response.json() as { errors?: { message: string }[] }
	return (body.errors ?? []).map((e) => e.message)
}

describe.each(requests)("access tokens verified with the userinfo endpoint (%s)", (_name, request) => {
	afterEach(() => {
		vi.restoreAllMocks()
	})

	it.each([
		["without email_verified", {}],
		["with email_verified true", { email_verified: true }],
	])("should issue a certificate for an opaque access token %s", async (_case, extra) => {
		const response = await request(createCa(), await getOpaqueAccessToken({ claims: { ...claims, ...extra } }))
		expect(response.status).toBe(200)

		const { certificate } = await response.json() as { certificate: string }
		expect(listCertificate(Buffer.from(certificate, "base64").toString()).keyId).toBe("user@example.com")
	})

	it("should refuse an access token for another subject than the identity token", async () => {
		const response = await request(createCa(), await getOpaqueAccessToken({ claims: { ...claims, sub: "someone-else" } }))
		expect(response.status).toBe(403)
	})

	it("should refuse an access token the userinfo endpoint does not accept, and log why", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		const response = await request(createCa({ LOG_LEVEL: "warning" }), "Bearer not-a-token")

		expect(response.status).toBe(400)
		expect(await errorMessages(response)).toContain("the access token was not accepted by the userinfo endpoint")
		expect(log).toHaveBeenCalledWith(expect.objectContaining({
			level: "warning",
			status: 401,
			authenticate: "Bearer error=\"invalid_token\"",
		}))
	})

	it("should verify a JWT access token with the userinfo endpoint rather than as a JWT", async () => {
		// the test IdP's userinfo endpoint only knows the opaque tokens it issued
		const response = await request(createCa(), await getAccessToken(claims))

		expect(response.status).toBe(400)
		expect(await errorMessages(response)).toContain("the access token was not accepted by the userinfo endpoint")
	})

	it.each([
		["email is missing", { sub }, "the userinfo response was missing required email claim"],
		["email is not an email address", { sub, email: "root" }, "the sub, email or email_verified claim of the userinfo response was not valid"],
		["sub is missing", { email: "user@example.com" }, "the sub, email or email_verified claim of the userinfo response was not valid"],
		["sub is empty", { sub: "", email: "user@example.com" }, "the sub, email or email_verified claim of the userinfo response was not valid"],
		["email_verified is not a boolean", { ...claims, email_verified: "true" }, "the sub, email or email_verified claim of the userinfo response was not valid"],
		["email_verified is false", { ...claims, email_verified: false }, "the email address in the userinfo response has not been verified by the IdP"],
	])("should refuse a userinfo response where %s", async (_case, userinfo, message) => {
		const response = await request(createCa(), await getOpaqueAccessToken({ claims: userinfo }))

		expect(response.status).toBe(400)
		expect(await errorMessages(response)).toContain(message)
	})

	it.each([
		["responds with a server error", { status: 500, raw: "{}" }],
		["does not respond with JSON", { status: 200, raw: "<html></html>" }],
		["does not respond with a JSON object", { status: 200, raw: JSON.stringify([claims]) }],
	])("should return a server error and log the cause when the userinfo endpoint %s", async (_case, userinfo) => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		const response = await request(createCa({ LOG_LEVEL: "error" }), await getOpaqueAccessToken(userinfo))

		expect(response.status).toBe(500)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({
			level: "error",
			message: "the access token could not be verified with the userinfo endpoint",
			error: expect.objectContaining({ name: "UserInfoUnavailableError" }),
		}))
	})

	it("should return a server error when the userinfo endpoint cannot be reached", async () => {
		// nothing listens on port 1
		const ca = createCa({ OIDC_USERINFO_URL: "http://127.0.0.1:1/userinfo" })

		const response = await request(ca, await getOpaqueAccessToken({ claims }))
		expect(response.status).toBe(500)
	})

	it("should not accept an opaque access token when no userinfo endpoint is configured", async () => {
		const response = await request(createCa({ OIDC_USERINFO_URL: undefined }), await getOpaqueAccessToken({ claims }))

		expect(response.status).toBe(400)
		expect(await errorMessages(response)).toContain("the access token was invalid")
	})
})
