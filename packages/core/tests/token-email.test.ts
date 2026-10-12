import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { tokenEmail } from "../src/utils.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken, type TokenClaims } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { listCertificate } from "./helpers/ssh-keygen.js"

const sub = "user123"
const userKey = ecdsaKey.user()
const publicKey = Buffer.from(userKey.publicKey).toString("base64")

// INCLUDE_SELF adds the local part of the email to the certificate's principals
const ca: SshCa = createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	SSH_CERTIFICATE_INCLUDE_SELF: true,
}))

// the claims of an access token, where the email claims may be of any type
type Claims = Omit<TokenClaims, "email"> & Record<string, unknown>

const requests: [string, (claims: Claims) => Promise<Response>][] = [
	["POST /api/v3/user/certificate", async (claims) => await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
		method: "POST",
		// tokens are requested with arbitrary claims, so the test IdP is given them as is
		headers: { "Content-Type": "application/json", "Authorization": await getAccessToken(claims as TokenClaims) },
		body: JSON.stringify({ public_key: publicKey, proof: generateProof(userKey), identity: await getIdentityToken({ sub, email: "user@example.com" }) }),
	}))],
	["POST /api/v4/user/certificates", async (claims) => await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await getAccessToken(claims as TokenClaims),
			"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
		},
		body: JSON.stringify({ public_key: publicKey, identity: await getIdentityToken({ sub, email: "user@example.com" }) }),
	}))],
]

describe.each(requests)("access token email claims (%s)", (_name, request) => {
	it.each([
		["without email_verified", {}],
		["with email_verified true", { email_verified: true }],
	])("should issue a certificate %s", async (_case, claims) => {
		const response = await request({ sub, email: "user@example.com", ...claims })
		expect(response.status).toBe(200)

		const { certificate } = await response.json() as { certificate: string }
		const listed = listCertificate(Buffer.from(certificate, "base64").toString())
		expect(listed.keyId).toBe("user@example.com")
		expect(listed.principals).toContain("user")
	})

	it.each([
		["email is missing", {}],
		["email is empty", { email: "" }],
		["email is not an email address", { email: "root" }],
		["email is a number", { email: 42 }],
		["email is a boolean", { email: true }],
		["email is a list", { email: ["a@example.com", "b@example.com"] }],
		["email is an object", { email: { address: "user@example.com" } }],
		["email_verified is false", { email: "user@example.com", email_verified: false }],
		["email_verified is not a boolean", { email: "user@example.com", email_verified: "true" }],
	])("should return 400 when %s", async (_case, claims) => {
		const response = await request({ sub, ...claims })
		expect(response.status).toBe(400)
	})
})

describe("tokenEmail", () => {
	it("should return the email address", () => {
		expect(tokenEmail({ email: "user@example.com", email_verified: true })).toEqual({ ok: true, email: "user@example.com" })
	})

	it("should reject an email address the IdP has not verified", () => {
		expect(tokenEmail({ email: "user@example.com", email_verified: false })).toMatchObject({ ok: false })
	})
})
