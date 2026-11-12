import { describe, expect, it } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { z } from "zod"
import ca, { createSshCa, InvalidConfigurationError, type SshCa } from "../src/index.js"
import { bindingsFromEnv, fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { CaDatabase, SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { generateRequestProof } from "./helpers/proof.js"
import { listCertificate } from "./helpers/ssh-keygen.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"

const sub = "user123"
const email = "user@example.com"

const CertificateResponse = z.object({ certificate: z.string() })

const newCa = (overrides: Partial<SshCaBindings> = {}): { ca: SshCa, sqlite: DatabaseSync } => {
	const sqlite = new DatabaseSync(":memory:")
	return {
		sqlite,
		ca: createSshCa(makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey), ...overrides })),
	}
}

// requests a user certificate with the groups claim of the identity token set
const request = async (ca: SshCa, groups: unknown): Promise<Response> => {
	const key = ecdsaKey.user()
	return await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Authorization": await getAccessToken({ sub, email }),
			"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates"),
		},
		body: JSON.stringify({ public_key: Buffer.from(key.publicKey).toString("base64"), identity: await getIdentityToken({ sub, email, groups }) }),
	}))
}

// the number of certificates recorded, where the table is only created when
// the database is first used
const recorded = (sqlite: DatabaseSync): unknown => sqlite.prepare("SELECT name FROM sqlite_master WHERE name = 'certificates'").get() === undefined
	? 0
	: (sqlite.prepare("SELECT count(*) AS n FROM certificates").get() as { n: number }).n

const unprocessable = (message: string) => ({
	success: false,
	result: {},
	errors: [{ code: 7007, message }],
})

describe("user certificate principals from the identity token", () => {
	it.each([
		["a comma", ["admins", "alice,root"], "alice,root"],
		["a comma, as a string claim", "alice,root", "alice,root"],
		["a tab", ["alice\troot"], "alice\troot"],
		["a newline", ["alice\nroot"], "alice\nroot"],
		["a control character", ["alice\u0000"], "alice\u0000"],
		["a wildcard", ["*"], "*"],
		["a pattern character", ["alice?"], "alice?"],
		["a negation", ["!alice"], "!alice"],
	])("should refuse a principal containing %s", async (_name, groups, principal) => {
		const { ca, sqlite } = newCa()

		const response = await request(ca, groups)

		expect(response.status).toBe(422)
		expect(await response.json()).toEqual(unprocessable(expect.stringContaining(`user certificate principal ${JSON.stringify(principal)}`)))
		expect(recorded(sqlite)).toBe(0)
	})

	it("should refuse an empty principal", async () => {
		const { ca } = newCa()

		const response = await request(ca, ["admins", ""])

		expect(response.status).toBe(422)
		expect(await response.json()).toEqual(unprocessable("user certificate principals must not be empty"))
	})

	it("should still replace spaces with underscores", async () => {
		const { ca } = newCa()

		const response = await request(ca, ["ops team"])

		expect(response.status).toBe(200)
		const certificate = Buffer.from(CertificateResponse.parse(await response.json()).certificate, "base64").toString()
		expect(listCertificate(certificate).principals).toEqual(["ops_team", "ssh-admin"])
	})
})

describe("SSH_CERTIFICATE_PRINCIPALS", () => {
	it.each([
		["a space inside a principal", "ssh-admin,ops team"],
		["an empty entry", "ssh-admin,,ops"],
		["a wildcard", "*"],
	])("should be refused by createSshCa with %s", (_name, principals) => {
		expect(() => newCa({ SSH_CERTIFICATE_PRINCIPALS: principals })).toThrow(InvalidConfigurationError)
		expect(() => newCa({ SSH_CERTIFICATE_PRINCIPALS: principals })).toThrow("SSH_CERTIFICATE_PRINCIPALS")
	})

	it("should be refused by createSshCa when an entry of a list is invalid", () => {
		expect(() => newCa({ SSH_CERTIFICATE_PRINCIPALS: ["ssh-admin", "ops team"] })).toThrow("SSH_CERTIFICATE_PRINCIPALS")
	})

	it("should trim each entry, as every list setting does", () => {
		expect(() => newCa({ SSH_CERTIFICATE_PRINCIPALS: "ssh-admin, ops" })).not.toThrow()
		expect(() => newCa({ SSH_CERTIFICATE_PRINCIPALS: ["ssh-admin", " ops "] })).not.toThrow()
	})

	it("should make the Workers default export answer with 500 when invalid", async () => {
		const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined, props: {} }

		const env = (principals: string): SshCaBindings => makeEnv({ PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey), SSH_CERTIFICATE_PRINCIPALS: principals })

		// the same request is served when the setting is valid
		expect((await ca.fetch(new Request("http://example.com/api/v4/ca"), env("ssh-admin,ops"), ctx)).status).toBe(200)

		const response = await ca.fetch(new Request("http://example.com/api/v4/ca"), env("ssh-admin,ops team"), ctx)
		expect(response.status).toBe(500)
	})

	it("should be refused by bindingsFromEnv when invalid", () => {
		const db: CaDatabase = { prepare: () => { throw new Error("not used") }, batch: async () => [], exec: async () => undefined }
		const source = {
			ISSUER_DN: "CN=SSH CA",
			JWT_JWKS_URL: "https://idp.example.com/.well-known/jwks.json",
			JWT_AUD: "audience",
			JWT_ISSUER: "https://idp.example.com",
			JWT_ALGORITHMS: "RS256",
			JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: "groups",
			SSH_CERTIFICATE_LIFETIME: "24 hours",
			SSH_CERTIFICATE_EXTENSIONS: "permit-pty",
			SSH_HOST_CERTIFICATE_LIFETIME: "30 days",
			CERTIFICATE_REQUEST_TIME_SKEW_MAX: "90 seconds",
			DB_CERTIFICATE_RETENTION: "1 year",
		}

		expect(() => bindingsFromEnv({ DB: db, PRIVATE_KEY: secretFromString("key") }, { ...source, SSH_CERTIFICATE_PRINCIPALS: "ssh-admin,ops team" }))
			.toThrow(/user certificate principal "ops team"[\s\S]*SSH_CERTIFICATE_PRINCIPALS/)
		expect(() => bindingsFromEnv({ DB: db, PRIVATE_KEY: secretFromString("key") }, { ...source, SSH_CERTIFICATE_PRINCIPALS: "ssh-admin,ops" }))
			.not.toThrow()
	})
})
