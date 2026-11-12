import { describe, it, expect } from "vitest"
import { createSshCa } from "../src/index.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import type { CaDatabase } from "../src/types.js"

// the key type and data of an OpenSSH public key, ignoring the comment
const keyBlob = (pub: string): string => pub.trim().split(" ").slice(0, 2).join(" ")

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

describe("createSshCa", () => {
	describe("fetch", () => {
		it("should serve requests using the bindings it was created with", async () => {
			const key = ecdsaKey.ca()
			const ca = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(key.privateKey) }))

			// only the request is passed, so the handler must supply the bindings itself
			const response = await ca.fetch(new Request("http://example.com/api/v4/ca"))

			expect(response.status).toBe(200)
			expect(keyBlob(await response.text())).toBe(keyBlob(key.publicKey))
		})

		it("should keep the bindings of separate instances apart", async () => {
			const first = ecdsaKey.ca()
			const second = ecdsaKey.user()
			const a = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(first.privateKey), ISSUER_DN: "CN=First CA" }))
			const b = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(second.privateKey), ISSUER_DN: "CN=Second CA" }))

			const fromA = await (await a.fetch(new Request("http://example.com/api/v4/ca"))).text()
			const fromB = await (await b.fetch(new Request("http://example.com/api/v4/ca"))).text()

			expect(fromA).toBe(`${keyBlob(first.publicKey)} CN=First CA\n`)
			expect(fromB).toBe(`${keyBlob(second.publicKey)} CN=Second CA\n`)
		})

		it("should respond with a 404 for unknown paths", async () => {
			const ca = createSshCa(makeEnv())

			const response = await ca.fetch(new Request("http://example.com/not-found"))

			expect(response.status).toBe(404)
		})

		it.each([
			["GET", "/api/v3"],
			["GET", "/api/v3/ca"],
			["GET", "/api/v3/user/krl"],
			["POST", "/api/v3/user/certificate"],
			["POST", "/api/v3/host/renew"],
			["DELETE", "/api/v3/user/certificates/1"],
		])("should respond to %s %s with a 410 as API v3 was removed", async (method, path) => {
			const ca = createSshCa(makeEnv())

			const response = await ca.fetch(new Request(`http://example.com${path}`, { method, body: method === "POST" ? "{}" : undefined }))

			expect(response.status).toBe(410)
			expect(await response.json()).toEqual({
				success: false,
				errors: [{ code: 410, message: "API v3 was removed in serverless-ssh-ca 1.0.0; upgrade ssh-ca-client to 0.24.0 or later" }],
				result: {},
			})
		})
	})

	describe("cleanup", () => {
		it("should not touch the database when retention is infinite", async () => {
			const { db, used } = trackedDatabase()
			const ca = createSshCa(makeEnv({ DB: db, DB_CERTIFICATE_RETENTION: "infinite" }))

			await ca.cleanup()

			expect(used).toEqual([])
		})

		it("should use the database when retention is limited", async () => {
			const { db, used } = trackedDatabase()
			const ca = createSshCa(makeEnv({ DB: db, DB_CERTIFICATE_RETENTION: "1 year" }))

			await ca.cleanup()

			expect(used).not.toEqual([])
		})
	})
})
