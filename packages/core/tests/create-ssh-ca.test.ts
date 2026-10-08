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
			const ca = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(key.toString("openssh")) }))

			// only the request is passed, so the handler must supply the bindings itself
			const response = await ca.fetch(new Request("http://example.com/api/v3/ca"))

			expect(response.status).toBe(200)
			expect(keyBlob(await response.text())).toBe(keyBlob(key.toPublic().toString("ssh")))
		})

		it("should keep the bindings of separate instances apart", async () => {
			const first = ecdsaKey.ca()
			const second = ecdsaKey.user()
			const a = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(first.toString("openssh")), ISSUER_DN: "CN=First CA" }))
			const b = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(second.toString("openssh")), ISSUER_DN: "CN=Second CA" }))

			const fromA = await (await a.fetch(new Request("http://example.com/api/v3/ca"))).text()
			const fromB = await (await b.fetch(new Request("http://example.com/api/v3/ca"))).text()

			expect(fromA).toBe(`${keyBlob(first.toPublic().toString("ssh"))} CN=First CA\n`)
			expect(fromB).toBe(`${keyBlob(second.toPublic().toString("ssh"))} CN=Second CA\n`)
		})

		it("should respond with a 404 for unknown paths", async () => {
			const ca = createSshCa(makeEnv())

			const response = await ca.fetch(new Request("http://example.com/not-found"))

			expect(response.status).toBe(404)
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
