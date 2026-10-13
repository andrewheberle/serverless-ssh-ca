import { afterEach, describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// the audience the test IdP issues tokens for unless a token sets its own
const audience = process.env.JWT_AUD ?? "audience"

const claims = { sub: "user123", email: "user@example.com" }
const userKey = ecdsaKey.user()
const publicKey = Buffer.from(userKey.publicKey).toString("base64")

const createCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	...overrides,
}))

// requests a user certificate from the v4 API with tokens issued for the given audiences
const requestV4 = async (ca: SshCa, aud: { access: string, identity: string }): Promise<Response> => {
	return await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await getAccessToken({ ...claims, aud: aud.access }),
			"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
		},
		body: JSON.stringify({
			public_key: publicKey,
			identity: await getIdentityToken({ ...claims, aud: aud.identity }),
		}),
	}))
}

// requests a user certificate from the v3 API with tokens issued for the given audiences
const requestV3 = async (ca: SshCa, aud: { access: string, identity: string }): Promise<Response> => {
	return await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await getAccessToken({ ...claims, aud: aud.access }),
		},
		body: JSON.stringify({
			public_key: publicKey,
			proof: generateProof(userKey),
			identity: await getIdentityToken({ ...claims, aud: aud.identity }),
		}),
	}))
}

describe.each([
	["v3", requestV3],
	["v4", requestV4],
])("token audience (%s)", (_version, request) => {
	afterEach(() => {
		vi.restoreAllMocks()
	})

	it("should issue a certificate when both tokens are for the configured audience", async () => {
		const response = await request(createCa(), { access: audience, identity: audience })
		expect(response.status).toBe(200)
	})

	it("should not accept an access token for another audience", async () => {
		const response = await request(createCa(), { access: "another-application", identity: audience })
		expect(response.status).toBe(400)
	})

	it("should not accept an identity token for another audience", async () => {
		const response = await request(createCa(), { access: audience, identity: "another-application" })
		expect(response.status).toBe(400)
	})

	it.each([
		["access", { access: "another-application", identity: audience }],
		["identity", { access: audience, identity: "another-application" }],
	])("should log the audience of an %s token for another audience", async (token, aud) => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		const response = await request(createCa({ LOG_LEVEL: "warning" }), aud)

		expect(response.status).toBe(400)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({
			level: "WARNING",
			message: `claim validation of the ${token} token failed`,
			claim: "aud",
			reason: "check_failed",
			value: "another-application",
		}))
	})

	it("should check the access token against JWT_ACCESS_TOKEN_AUD when it is set", async () => {
		const ca = createCa({ JWT_ACCESS_TOKEN_AUD: "api" })

		expect((await request(ca, { access: "api", identity: audience })).status).toBe(200)
		expect((await request(ca, { access: audience, identity: audience })).status).toBe(400)
		// the identity token is still checked against JWT_AUD
		expect((await request(ca, { access: "api", identity: "api" })).status).toBe(400)
	})

	it.each([
		["empty", ""],
		["an empty list", []],
		["unset", undefined],
	])("should return a server error when JWT_AUD is %s", async (_name, aud) => {
		// JWT_AUD is required, but on Workers vars are not validated before use
		const ca = createCa({ JWT_AUD: aud as SshCaBindings["JWT_AUD"] })

		const response = await request(ca, { access: audience, identity: audience })
		expect(response.status).toBe(500)
	})
})
