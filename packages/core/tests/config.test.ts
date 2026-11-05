import { afterEach, describe, expect, it, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { z } from "zod"
import ca, { createSshCa, InvalidConfigurationError } from "../src/index.js"
import { recordCertificate, revokeCertificate } from "../src/db/index.js"
import { CertificateType } from "../src/db/types.js"
import { bindingsFromEnv, fromNodeSqlite, InvalidConfigurationError as NodeInvalidConfigurationError, secretFromString } from "../src/node/index.js"
import { MissingIssuerError, verifyJWT } from "../src/verify.js"
import type { CaDatabase, SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { hostCertificate } from "./helpers/certificate.js"
import { MockSecretStore } from "./helpers/secret.js"
import { isRevoked } from "./helpers/ssh-keygen.js"
import { getIdentityToken } from "./helpers/token.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

afterEach(() => {
	vi.restoreAllMocks()
})

// configuration values that were accepted before they were validated, and
// either turned a check off or did something other than what was meant
const invalid: [keyof SshCaBindings, string | undefined][] = [
	["CERTIFICATE_REQUEST_TIME_SKEW_MAX", "garbage"],
	["CERTIFICATE_REQUEST_TIME_SKEW_MAX", "90 secs"],
	["JWT_ISSUER", ""],
	["JWT_ISSUER", undefined],
	["DB_CERTIFICATE_RETENTION", "-1 day"],
]

// a database that records any use of it
const trackedDatabase = (): { db: CaDatabase, used: PropertyKey[] } => {
	const used: PropertyKey[] = []
	const db = new Proxy({}, {
		get(_, prop) {
			used.push(prop)
			throw new Error("database should not be used")
		},
	}) as unknown as CaDatabase
	return { db, used }
}

// an execution context that records the promises it is asked to wait for
const executionContext = () => {
	const waited: Promise<unknown>[] = []
	return {
		ctx: { waitUntil: (promise: Promise<unknown>) => { waited.push(promise) }, passThroughOnException: () => undefined, props: {} },
		waited,
	}
}

describe("createSshCa", () => {
	it.each(invalid)("should refuse %s of %j", (key, value) => {
		const env = makeEnv({ [key]: value })

		expect(() => createSshCa(env)).toThrow(InvalidConfigurationError)
		expect(() => createSshCa(env)).toThrow(key)
	})

	it("should throw the same error as bindingsFromEnv", () => {
		expect(InvalidConfigurationError).toBe(NodeInvalidConfigurationError)
	})

	it("should accept a skew of zero", () => {
		expect(() => createSshCa(makeEnv({ CERTIFICATE_REQUEST_TIME_SKEW_MAX: "0 seconds" }))).not.toThrow()
	})

	it.each([
		["SSH_CERTIFICATE_LIFETIME", "0 seconds"],
		["SSH_HOST_CERTIFICATE_LIFETIME", "24 hrs"],
		["DB_CERTIFICATE_RETENTION", "0 days"],
		["DB_CERTIFICATE_RETENTION", "1 fortnight"],
		["SSH_CERTIFICATE_INCLUDE_SELF", "yes"],
	])("should refuse %s of %j", (key, value) => {
		expect(() => createSshCa(makeEnv({ [key]: value }))).toThrow(key)
	})
})

describe("Workers default export", () => {
	const errorBody = { success: false, errors: [{ code: 7000, message: "Internal Server Error" }] }

	it.each(invalid)("should answer every request with 500 for %s of %j", async (key, value) => {
		const env = makeEnv({ [key]: value })
		const { ctx } = executionContext()

		for (const path of ["/api/v4/ca", "/api/v4/user/krl", "/openapi.json"]) {
			const response = await ca.fetch(new Request(`http://example.com${path}`), env, ctx)
			expect(response.status).toBe(500)

			// the body does not describe the configuration
			const body: unknown = await response.json()
			expect(body).toEqual(errorBody)
			expect(JSON.stringify(body)).not.toContain(key)
		}
	})

	it("should log why the configuration is invalid once at error level", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const env = makeEnv({ LOG_LEVEL: "error", CERTIFICATE_REQUEST_TIME_SKEW_MAX: "90 secs" })
		const { ctx } = executionContext()

		await ca.fetch(new Request("http://example.com/api/v4/ca"), env, ctx)
		await ca.fetch(new Request("http://example.com/api/v4/ca"), env, ctx)
		await ca.scheduled(undefined, env, ctx)

		expect(log).toHaveBeenCalledTimes(1)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({
			level: "error",
			error: expect.stringContaining("CERTIFICATE_REQUEST_TIME_SKEW_MAX"),
		}))
	})

	it("should skip cleanup when the configuration is invalid", async () => {
		const { db, used } = trackedDatabase()
		const { ctx, waited } = executionContext()

		await ca.scheduled(undefined, makeEnv({ DB: db, JWT_ISSUER: "" }), ctx)

		expect(waited).toEqual([])
		expect(used).toEqual([])
	})

	it("should serve requests when the configuration is valid", async () => {
		const env = makeEnv({ PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey) })
		const { ctx } = executionContext()

		const response = await ca.fetch(new Request("http://example.com/api/v4/ca"), env, ctx)
		expect(response.status).toBe(200)
	})
})

describe("bindingsFromEnv", () => {
	const valid: Record<string, string> = {
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
	const { db } = trackedDatabase()

	it.each(invalid)("should refuse %s of %j", (key, value) => {
		const source = { ...valid, [key]: value }

		expect(() => bindingsFromEnv({ DB: db, PRIVATE_KEY: secretFromString("key") }, source)).toThrow(InvalidConfigurationError)
		expect(() => bindingsFromEnv({ DB: db, PRIVATE_KEY: secretFromString("key") }, source)).toThrow(key)
	})
})

describe("verifyJWT", () => {
	it.each([
		["empty", ""],
		["whitespace", " "],
	])("should throw when the issuer is %s", async (_name, issuer) => {
		const token = await getIdentityToken({ sub: "user123", email: "user@example.com" })

		await expect(verifyJWT(makeEnv({ JWT_ISSUER: issuer }), token, "audience")).rejects.toBeInstanceOf(MissingIssuerError)
	})
})

describe("database cleanup", () => {
	const KrlResponse = z.object({ krl: z.string() })

	const setup = () => {
		const sqlite = new DatabaseSync(":memory:")
		const env = makeEnv({
			DB: fromNodeSqlite(sqlite),
			PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey),
			DB_CERTIFICATE_RETENTION: "1 hour",
		})

		// records a host certificate that expired some hours ago
		const expired = async (hours: number, revoked: boolean) => {
			const certificate = hostCertificate(ecdsaKey.ca(), ecdsaKey.host())
			await recordCertificate(env, certificate, certificate.keyId, CertificateType.Host)
			if (revoked) {
				await revokeCertificate(env, { serial: certificate.serial, certificateType: CertificateType.Host, revoker: { kind: "keyHolder", publicKey: certificate.publicKey } })
			}
			sqlite.prepare("UPDATE certificates SET valid_before = ? WHERE serial = ?")
				.run(new Date(Date.now() - hours * 60 * 60 * 1000).toISOString(), `${certificate.serial}`)

			return certificate
		}

		const recorded = (serial: bigint): boolean => sqlite.prepare("SELECT serial FROM certificates WHERE serial = ?").get(`${serial}`) !== undefined

		return { env, expired, recorded }
	}

	it("should keep a revoked certificate while it is still in the KRL", async () => {
		const { env, expired, recorded } = setup()
		const certificate = await expired(2, true)
		const ca = createSshCa(env)

		await ca.cleanup()

		expect(recorded(certificate.serial)).toBe(true)

		const response = await ca.fetch(new Request("http://example.com/api/v4/host/krl"))
		expect(response.status).toBe(200)
		const krl = Buffer.from(KrlResponse.parse(await response.json()).krl, "base64")
		expect(isRevoked(krl, certificate.toString())).toBe(true)
	})

	it("should remove a revoked certificate once it has left the KRL", async () => {
		const { env, expired, recorded } = setup()
		const certificate = await expired(25, true)

		await createSshCa(env).cleanup()

		expect(recorded(certificate.serial)).toBe(false)
	})

	it("should remove a certificate that is not revoked after the retention period", async () => {
		const { env, expired, recorded } = setup()
		const certificate = await expired(2, false)

		await createSshCa(env).cleanup()

		expect(recorded(certificate.serial)).toBe(false)
	})
})
