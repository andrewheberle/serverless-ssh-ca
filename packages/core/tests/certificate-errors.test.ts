import { afterEach, describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken, type TokenClaims } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const userKey = ecdsaKey.user()
const publicKey = Buffer.from(userKey.publicKey).toString("base64")
const claims: TokenClaims = { sub: "user123", email: "user@example.com" }

const createCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	...overrides,
}))

type Request = (ca: SshCa, body: Record<string, unknown>) => Promise<Response>

const requests: [string, Request][] = [
	["POST /api/v3/user/certificate", async (ca, body) => await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
		method: "POST",
		headers: { "Content-Type": "application/json", "Authorization": await getAccessToken(claims) },
		body: JSON.stringify({ public_key: publicKey, proof: generateProof(userKey), identity: await getIdentityToken(claims), ...body }),
	}))],
	["POST /api/v4/user/certificates", async (ca, body) => await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await getAccessToken(claims),
			"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
		},
		body: JSON.stringify({ public_key: publicKey, identity: await getIdentityToken(claims), ...body }),
	}))],
]

const errorMessages = async (response: Response): Promise<string[]> => {
	const body = await response.json() as { errors?: { message: string }[] }
	return (body.errors ?? []).map((e) => e.message)
}

describe.each(requests)("certificate errors (%s)", (_name, request) => {
	it("should issue a certificate with allowed extensions", async () => {
		const response = await request(createCa(), { extensions: ["permit-pty"] })
		expect(response.status).toBe(200)
	})

	it("should return 422 for an extension that is not allowed", async () => {
		const response = await request(createCa(), { extensions: ["permit-pty", "permit-everything"] })
		expect(response.status).toBe(422)
		expect(await errorMessages(response)).toContain("permit-everything is not allowed")
	})

	it("should return 422 when the certificate would have no principals", async () => {
		// no static principals and no principals claim in the identity token
		const response = await request(createCa({ SSH_CERTIFICATE_PRINCIPALS: undefined }), {})
		expect(response.status).toBe(422)
		expect(await errorMessages(response)).toContain("a certificate must have at least one principal")
	})
})

describe.each(requests)("CA key errors (%s)", (_name, request) => {
	afterEach(() => {
		vi.restoreAllMocks()
	})

	it("should return 500 and log why the CA key could not be parsed", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const ca = createCa({
			PRIVATE_KEY: secretFromString("-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n"),
			LOG_LEVEL: "error",
		})

		const response = await request(ca, {})

		// chanfana hides the message of a 500 from clients, so the reason is
		// only in the logs
		expect(response.status).toBe(500)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({
			level: "ERROR",
			message: "error parsing private key: private key could not be decoded",
			error: expect.objectContaining({ name: "KeyParseError", message: "private key could not be decoded", cause: expect.objectContaining({ message: expect.any(String) }) }),
		}))
	})
})
