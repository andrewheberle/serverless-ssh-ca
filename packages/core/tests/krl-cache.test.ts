import { describe, it, expect, vi, afterEach } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type CaCache, type SshCa } from "../src/index.js"
import { cacheInMemory, fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { dbCleanup, getKrlRevision, recordCertificate, recordRenewal, revokeCertificate } from "../src/db/index.js"
import { hostCertificate } from "./helpers/certificate.js"
import { CertificateType } from "../src/db/types.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof } from "./helpers/proof.js"
import { listCertificate } from "./helpers/ssh-keygen.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const claims = { sub: "user123", email: "user@example.com" }

describe("KRL revision", () => {
	const setup = () => {
		const sqlite = new DatabaseSync(":memory:")
		const env = makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey) })
		const issue = async () => hostCertificate(ecdsaKey.ca(), ecdsaKey.host())
		return { sqlite, env, issue }
	}

	it("should increment when a certificate of its type is revoked", async () => {
		const { env, issue } = setup()
		const certificate = await issue()
		await recordCertificate(env, certificate, certificate.keyId, CertificateType.Host)

		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)
		await revokeCertificate(env, certificate.serial)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
		expect(await getKrlRevision(env, CertificateType.User)).toBe(0n)
	})

	it("should not increment when a certificate is already revoked", async () => {
		const { env, issue } = setup()
		const certificate = await issue()
		await recordCertificate(env, certificate, certificate.keyId, CertificateType.Host)
		await revokeCertificate(env, certificate.serial)

		expect(await revokeCertificate(env, certificate.serial)).toEqual([])
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
	})

	it("should increment when a host certificate is renewed", async () => {
		const { env, issue } = setup()
		const previous = await issue()
		await recordCertificate(env, previous, previous.keyId, CertificateType.Host)

		expect(await recordRenewal(env, previous, await issue())).toBe(true)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)

		// a renewal that is not recorded does not revoke anything
		expect(await recordRenewal(env, previous, await issue())).toBe(false)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
	})

	it("should increment when cleanup removes certificates", async () => {
		const { sqlite, env, issue } = setup()
		const certificate = await issue()
		await recordCertificate(env, certificate, certificate.keyId, CertificateType.Host)

		// nothing has expired, so nothing is removed
		await dbCleanup(env)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)

		sqlite.prepare("UPDATE certificates SET valid_before = ?").run(new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000).toISOString())
		await dbCleanup(env)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
		expect(await getKrlRevision(env, CertificateType.User)).toBe(1n)
	})
})

describe("cacheInMemory", () => {
	afterEach(() => {
		vi.useRealTimers()
	})

	it("should return values until they expire", async () => {
		vi.useFakeTimers({ toFake: ["Date"] })
		vi.setSystemTime(new Date("2026-10-12T00:00:00Z"))
		const cache = cacheInMemory()

		expect(await cache.get("a")).toBeNull()
		await cache.put("a", "1", { expirationTtl: 60 })
		await cache.put("b", "2")
		expect(await cache.get("a")).toBe("1")

		vi.setSystemTime(new Date("2026-10-12T00:01:00Z"))
		expect(await cache.get("a")).toBeNull()
		expect(await cache.get("b")).toBe("2")
	})
})

describe("cached KRLs", () => {
	// a cache that records the keys written to it
	const recordingCache = (inner: CaCache = cacheInMemory()): CaCache & { puts: string[] } => {
		const puts: string[] = []
		return {
			puts,
			get: async (key) => await inner.get(key),
			put: async (key, value, options) => {
				puts.push(key)
				await inner.put(key, value, options)
			},
		}
	}

	const setup = (cache: CaCache, privateKey = ed25519Key.ca().privateKey) => {
		const sqlite = new DatabaseSync(":memory:")
		const env: SshCaBindings = makeEnv({ DB: fromNodeSqlite(sqlite), PRIVATE_KEY: secretFromString(privateKey), CACHE: cache })
		return { sqlite, env, ca: createSshCa(env) }
	}

	const getKrl = async (ca: SshCa): Promise<unknown> => {
		const response = await ca.fetch(new Request("http://example.com/api/v4/user/krl"))
		expect(response.status).toBe(200)
		return await response.json()
	}

	// issues a user certificate, returning its serial
	const issue = async (ca: SshCa): Promise<bigint> => {
		const key = ecdsaKey.user()
		const response = await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
			method: "POST",
			headers: { "Content-Type": "application/json", "Authorization": await getAccessToken(claims) },
			body: JSON.stringify({ public_key: Buffer.from(key.publicKey).toString("base64"), proof: generateProof(key), identity: await getIdentityToken(claims) }),
		}))
		expect(response.status).toBe(200)
		const { certificate } = await response.json() as { certificate: string }
		return listCertificate(Buffer.from(certificate, "base64").toString()).serial
	}

	const revoke = async (ca: SshCa, serial: bigint): Promise<void> => {
		const key = ecdsaKey.user()
		const response = await ca.fetch(new Request("http://example.com/api/v3/user/revoke", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ serial: `${serial}`, public_key: Buffer.from(key.publicKey).toString("base64"), proof: generateProof(key) }),
		}))
		expect(response.status).toBe(200)
	}

	it("should serve the cached KRL until a certificate is revoked", async () => {
		const cache = recordingCache()
		const { sqlite, ca } = setup(cache)
		const serial = await issue(ca)

		const first = await getKrl(ca)
		expect(cache.puts).toHaveLength(1)

		// a change made outside the CA does not increment the revision, which
		// shows the second KRL comes from the cache
		sqlite.prepare("UPDATE certificates SET revoked_at = ?").run(new Date().toISOString())
		expect(await getKrl(ca)).toEqual(first)
		expect(cache.puts).toHaveLength(1)

		sqlite.prepare("UPDATE certificates SET revoked_at = NULL").run()
		await revoke(ca, serial)
		const second = await getKrl(ca)
		expect(second).not.toEqual(first)
		expect(cache.puts).toHaveLength(2)
		expect(cache.puts[0]).not.toBe(cache.puts[1])
	})

	it("should not use a KRL cached for another CA key", async () => {
		const shared = cacheInMemory()
		const first = recordingCache(shared)
		await getKrl(setup(first, ed25519Key.ca().privateKey).ca)
		const second = recordingCache(shared)
		await getKrl(setup(second, ecdsaKey.ca().privateKey).ca)

		expect(first.puts).toHaveLength(1)
		expect(second.puts).toHaveLength(1)
		expect(first.puts[0]).not.toBe(second.puts[0])
	})

	it("should generate the KRL again when the cached value is not valid", async () => {
		const cache = recordingCache()
		const { ca } = setup(cache)
		const first = await getKrl(ca)
		const key = cache.puts[0]
		expect(key).toBeDefined()

		await cache.put(key ?? "", "not json")
		expect(await getKrl(ca)).toEqual(first)
		await cache.put(key ?? "", JSON.stringify({ krl: 1 }))
		expect(await getKrl(ca)).toEqual(first)
	})

	it("should still serve the KRL when the cache fails", async () => {
		const failing: CaCache = {
			get: async () => { throw new Error("cache unavailable") },
			put: async () => { throw new Error("cache unavailable") },
		}
		const { ca } = setup(failing)

		expect(await getKrl(ca)).toMatchObject({ krl: expect.any(String), signature: expect.any(String) })
	})
})
