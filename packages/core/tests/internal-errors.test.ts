import { afterEach, describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { generateRequestProof } from "./helpers/proof.js"
import { signCertificate } from "./helpers/ssh-keygen.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as rsaKey } from "./keys/rsa.js"

// A 500 never tells the client why the request failed: chanfana sends the
// same body for every InternalServerErrorException, and the reason is only
// logged. These tests cover each place the API answers with a 500 for a
// reason of its own.

const caKey = ed25519Key.ca()
const hostKey = ecdsaKey.host()
const userKey = ecdsaKey.user()

const internalError = {
	success: false,
	result: null,
	errors: [{ code: 7009, message: "Internal Error" }],
}

// a database that has been closed, so every use of it throws
const closedDatabase = (): SshCaBindings["DB"] => {
	const db = new DatabaseSync(":memory:")
	db.close()
	return fromNodeSqlite(db)
}

const createCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(caKey.privateKey),
	LOG_LEVEL: "error",
	...overrides,
}))

const get = async (ca: SshCa, path: string): Promise<Response> => await ca.fetch(new Request(`http://example.com${path}`))

const expectInternalError = async (response: Response): Promise<void> => {
	expect(response.status).toBe(500)
	expect(await response.json()).toEqual(internalError)
}

describe("500 responses", () => {
	afterEach(() => {
		vi.restoreAllMocks()
	})

	describe.each(["/api/v4/ca", "/api/v4/host/krl"])("GET %s", (path) => {
		it("should return 500 and log why for a CA key of a type that is not supported", async () => {
			const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

			await expectInternalError(await get(createCa({ PRIVATE_KEY: secretFromString(rsaKey.ca().privateKey) }), path))
			expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: expect.stringContaining("not supported") }))
		})

		it("should return 500 and log why for a CA key that cannot be parsed", async () => {
			const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

			await expectInternalError(await get(createCa({ PRIVATE_KEY: secretFromString("not a key") }), path))
			expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: expect.stringContaining("error parsing private key") }))
		})
	})

	it("should return 500 and log why when the database cannot be used for a KRL", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		await expectInternalError(await get(createCa({ DB: closedDatabase() }), "/api/v4/host/krl"))
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: "unhandled error" }))
	})

	it("should return 500 and log why when the database cannot be used for a renewal", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const serial = 1234n
		const certificate = signCertificate(caKey, hostKey.publicKey, { kind: "host", keyId: "host_test_host", principals: ["test_host"], validity: "-1m:+2d", serial })
		const path = `/api/v4/host/certificates/${serial}/renew`

		const response = await createCa({ DB: closedDatabase() }).fetch(new Request(`http://example.com${path}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Proof-Of-Possession": generateRequestProof(hostKey, "POST", path),
			},
			body: JSON.stringify({ certificate: Buffer.from(certificate).toString("base64") }),
		}))

		await expectInternalError(response)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error" }))
	})

	it("should return 500 and log why when the CA key cannot be read for a renewal", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const serial = 1234n
		const certificate = signCertificate(caKey, hostKey.publicKey, { kind: "host", keyId: "host_test_host", principals: ["test_host"], validity: "-1m:+2d", serial })
		const path = `/api/v4/host/certificates/${serial}/renew`
		// a secret store that cannot be reached, which is not a problem with the key itself
		const unavailable = { get: async (): Promise<string> => await Promise.reject(new Error("secret store unavailable")) }

		const response = await createCa({ PRIVATE_KEY: unavailable }).fetch(new Request(`http://example.com${path}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Proof-Of-Possession": generateRequestProof(hostKey, "POST", path),
			},
			body: JSON.stringify({ certificate: Buffer.from(certificate).toString("base64") }),
		}))

		await expectInternalError(response)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: "unhandled error" }))
	})

	it("should return 500 and log why when the database cannot be used for a revocation", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const path = "/api/v4/user/certificates/1234"

		const response = await createCa({ DB: closedDatabase() }).fetch(new Request(`http://example.com${path}`, {
			method: "DELETE",
			headers: { "Proof-Of-Possession": generateRequestProof(userKey, "DELETE", path) },
		}))

		await expectInternalError(response)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: "unhandled error" }))
	})
})
