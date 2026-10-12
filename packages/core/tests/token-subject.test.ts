import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { tokenSubject, TokenClaimError } from "../src/utils.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken, type TokenClaims } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const email = "user@example.com"
const userKey = ecdsaKey.user()
const hostKey = ecdsaKey.host()
const publicKey = (key: { publicKey: string }): string => Buffer.from(key.publicKey).toString("base64")

const ca: SshCa = createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
}))

// the claims of a token, where sub may be left out or of the wrong type
type Claims = Omit<TokenClaims, "sub"> & { sub?: unknown }

// tokens are requested with arbitrary claims, so the test IdP is given them as is
const token = async (get: typeof getAccessToken, claims: Claims): Promise<string> => await get(claims as TokenClaims)

type Tokens = { access: Claims, identity: Claims }

const requests: [string, (tokens: Tokens) => Promise<Response>][] = [
	["POST /api/v3/user/certificate", async ({ access, identity }) => await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
		method: "POST",
		headers: { "Content-Type": "application/json", "Authorization": await token(getAccessToken, access) },
		body: JSON.stringify({ public_key: publicKey(userKey), proof: generateProof(userKey), identity: await token(getIdentityToken, identity) }),
	}))],
	["POST /api/v3/host/certificate", async ({ access, identity }) => await ca.fetch(new Request("http://example.com/api/v3/host/certificate", {
		method: "POST",
		headers: { "Content-Type": "application/json", "Authorization": await token(getAccessToken, access) },
		body: JSON.stringify({ public_key: publicKey(hostKey), proof: generateProof(hostKey), identity: await token(getIdentityToken, identity), principals: ["test_host"] }),
	}))],
	["POST /api/v4/user/certificates", async ({ access, identity }) => await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await token(getAccessToken, access),
			"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
		},
		body: JSON.stringify({ public_key: publicKey(userKey), identity: await token(getIdentityToken, identity) }),
	}))],
	["POST /api/v4/host/certificates", async ({ access, identity }) => await ca.fetch(new Request("http://example.com/api/v4/host/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await token(getAccessToken, access),
			"Proof-Of-Possession": generateRequestProof(hostKey, "POST", "/api/v4/host/certificates"),
		},
		body: JSON.stringify({ public_key: publicKey(hostKey), identity: await token(getIdentityToken, identity), principals: ["test_host"] }),
	}))],
]

describe.each(requests)("token subjects (%s)", (_name, request) => {
	it("should issue a certificate when both tokens have the same subject", async () => {
		const response = await request({ access: { sub: "user123", email }, identity: { sub: "user123", email } })
		expect(response.status).toBe(200)
	})

	it("should not issue a certificate when the tokens have different subjects", async () => {
		const response = await request({ access: { sub: "user123", email }, identity: { sub: "user456", email } })
		expect(response.status).toBe(403)
	})

	it("should not issue a certificate when neither token has a subject", async () => {
		const response = await request({ access: { email: "victim@example.com" }, identity: { email } })
		expect(response.status).toBe(400)
	})

	it.each([
		["missing", undefined],
		["empty", ""],
		["a number", 123],
		["a list", ["user123"]],
	])("should not issue a certificate when the access token subject is %s", async (_case, sub) => {
		const response = await request({ access: { sub, email }, identity: { sub: "user123", email } })
		expect(response.status).toBe(400)
	})

	it.each([
		["missing", undefined],
		["empty", ""],
		["a number", 123],
		["a list", ["user123"]],
	])("should not issue a certificate when the identity token subject is %s", async (_case, sub) => {
		const response = await request({ access: { sub: "user123", email }, identity: { sub, email } })
		expect(response.status).toBe(400)
	})
})

describe("tokenSubject", () => {
	it("should return the subject", () => {
		expect(tokenSubject({ sub: "user123" })).toBe("user123")
	})

	it.each([undefined, "", 123, null, ["user123"]])("should throw for %j", (sub) => {
		expect(() => tokenSubject({ sub })).toThrow(TokenClaimError)
	})
})
