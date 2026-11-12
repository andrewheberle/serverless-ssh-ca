import { describe, it, expect, beforeAll, afterAll } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { z } from "zod"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { KRLBuilder } from "../src/krl.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateRequestProof } from "./helpers/proof.js"
import { fingerprint, listCertificate } from "./helpers/ssh-keygen.js"
import type { TestKey } from "./keys/types.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { priv, pub } from "./helpers/keys.js"

const email = "user@example.com"
const claims = { sub: "user123", email }

const CertificateResponse = z.object({ certificate: z.string() })
const KrlResponse = z.object({ krl: z.string(), signature: z.string() })

// fetch a KRL and return it with the version from its header
const getKrl = async (ca: SshCa, type: "user" | "host" = "user"): Promise<{ krl: Buffer, version: bigint, generatedAt: Date }> => {
	const response = await ca.fetch(new Request(`http://example.com/api/v4/${type}/krl`))
	expect(response.status).toBe(200)
	const krl = Buffer.from(KrlResponse.parse(await response.json()).krl, "base64")
	// the header is the magic, format version, KRL version and generation date
	return { krl, version: krl.readBigUInt64BE(12), generatedAt: new Date(Number(krl.readBigUInt64BE(20)) * 1000) }
}

const caFor = (sqlite: DatabaseSync): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(sqlite),
	PRIVATE_KEY: secretFromString(ecdsaKey.ca().privateKey),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
}))

const post = async (ca: SshCa, path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> => {
	return await ca.fetch(new Request(`http://example.com${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: JSON.stringify(body),
	}))
}

const publicKey = (key: TestKey): string => Buffer.from(key.publicKey).toString("base64")

// request a certificate of a type for a key, with principals for a host certificate
const issue = async (ca: SshCa, type: "user" | "host", key: TestKey, principals?: string[]): Promise<Response> => {
	const path = `/api/v4/${type}/certificates`
	return await post(ca, path, {
		public_key: publicKey(key),
		identity: await getIdentityToken(claims),
		...(principals === undefined ? {} : { principals }),
	}, {
		"Authorization": await getAccessToken(claims),
		"Proof-Of-Possession": generateRequestProof(key, "POST", path),
	})
}

// renew a BASE64 encoded host certificate with a proof of possession of its key
const renew = async (ca: SshCa, certificate: string, key: TestKey): Promise<Response> => {
	const path = `/api/v4/host/certificates/${listCertificate(Buffer.from(certificate, "base64").toString()).serial}/renew`
	return await post(ca, path, { certificate }, { "Proof-Of-Possession": generateRequestProof(key, "POST", path) })
}

// revoke a certificate of a type by its serial, with a proof of possession of a key
const revoke = async (ca: SshCa, type: string, serial: bigint, key: TestKey): Promise<Response> => {
	const path = `/api/v4/${type}/certificates/${serial}`
	return await ca.fetch(new Request(`http://example.com${path}`, {
		method: "DELETE",
		headers: { "Proof-Of-Possession": generateRequestProof(key, "DELETE", path) },
	}))
}

// request a certificate and return its serial
const requestUserCertificate = async (ca: SshCa, key: TestKey): Promise<bigint> => {
	const response = await issue(ca, "user", key)
	expect(response.status).toBe(200)

	const { certificate } = CertificateResponse.parse(await response.json())
	return listCertificate(Buffer.from(certificate, "base64").toString()).serial
}

describe("running on Node.js with node:sqlite", () => {
	let sqlite: DatabaseSync
	let ca: SshCa

	beforeAll(() => {
		sqlite = new DatabaseSync(":memory:")
		ca = caFor(sqlite)
	})

	afterAll(() => {
		sqlite.close()
	})

	it("should create the schema and record issued user certificates", async () => {
		const key = ecdsaKey.user()
		const serial = await requestUserCertificate(ca, key)

		expect(sqlite.prepare("SELECT name FROM migrations").all()).toEqual([{ name: "0001_initial_schema" }, { name: "0002_krl_version" }, { name: "0003_krl_revision" }, { name: "0004_certificate_audit" }, { name: "0005_renewal_of" }, { name: "0006_client_address" }])
		expect(sqlite.prepare("SELECT key_id, principals, certificate_type, public_key, revoked_at FROM certificates WHERE serial = ?").all(`${serial}`)).toEqual([{
			key_id: email,
			principals: "UID=ssh-admin",
			certificate_type: 0,
			public_key: expect.stringContaining(key.publicKey.split(" ").slice(0, 2).join(" ")),
			revoked_at: null,
		}])
	})

	it("should only apply migrations once", async () => {
		await requestUserCertificate(ca, ecdsaKey.user())

		expect(sqlite.prepare("SELECT count(*) AS n FROM migrations").get()).toEqual({ n: 6 })
	})

	it("should record issued host certificates", async () => {
		const key = ecdsaKey.host()
		const response = await issue(ca, "host", key, ["test_host"])
		expect(response.status).toBe(200)

		expect(sqlite.prepare("SELECT key_id, certificate_type FROM certificates WHERE certificate_type = 1").all()).toEqual([
			{ key_id: "host_test_host", certificate_type: 1 },
		])
	})

	it("should not issue a host certificate for a wildcard principal", async () => {
		const key = ecdsaKey.host()
		const response = await issue(ca, "host", key, ["test_host", "*"])
		expect(response.status).toBe(400)
		expect(sqlite.prepare("SELECT serial FROM certificates WHERE principals LIKE '%*%'").all()).toEqual([])
	})

	it("should revoke a certificate and include it in the KRL", async () => {
		const key = ecdsaKey.user()
		const serial = await requestUserCertificate(ca, key)

		const response = await revoke(ca, "user", serial, key)
		expect(response.status).toBe(200)
		expect(await response.json()).toEqual({ revoked_at: expect.any(String) })

		// a second revocation conflicts with the first
		expect((await revoke(ca, "user", serial, key)).status).toBe(409)

		const { krl, generatedAt } = await getKrl(ca)
		// the first user KRL generated by this CA, so the first version after 1
		const expected = new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([serial]).generate(2n, "", generatedAt)
		expect(krl).toEqual(Buffer.from(expected))
	})

	it("should not revoke a certificate issued for another key", async () => {
		const serial = await requestUserCertificate(ca, ecdsaKey.user())
		const other = ecdsaKey.host()

		const response = await revoke(ca, "user", serial, other)
		expect(response.status).toBe(404)
	})

	it("should renew a host certificate", async () => {
		const key = ecdsaKey.host()
		const issued = await issue(ca, "host", key, ["renewed_host"])
		expect(issued.status).toBe(200)
		const { certificate } = CertificateResponse.parse(await issued.json())

		const response = await renew(ca, certificate, key)
		expect(response.status).toBe(200)
		const renewed = listCertificate(Buffer.from(CertificateResponse.parse(await response.json()).certificate, "base64").toString())
		expect(renewed.kind).toBe("host")
		expect(renewed.principals).toEqual(["renewed_host"])
		expect(renewed.publicKey).toBe(fingerprint(key.publicKey))

		// the certificate that was renewed is revoked, so cannot be renewed again
		const previous = listCertificate(Buffer.from(certificate, "base64").toString())
		expect(sqlite.prepare("SELECT revoked_at FROM certificates WHERE serial = ?").get(`${previous.serial}`)).toEqual({ revoked_at: expect.any(String) })
		expect(sqlite.prepare("SELECT revoked_at FROM certificates WHERE serial = ?").get(`${renewed.serial}`)).toEqual({ revoked_at: null })
		const repeated = await renew(ca, certificate, key)
		expect(repeated.status).toBe(400)
	})

	it("should not renew a user certificate", async () => {
		const key = ecdsaKey.user()
		const issued = await issue(ca, "user", key)
		expect(issued.status).toBe(200)
		const { certificate } = CertificateResponse.parse(await issued.json())

		// renewal does not need OIDC authentication, so must not extend a user certificate
		const response = await renew(ca, certificate, key)
		expect(response.status).toBe(400)
		expect(JSON.stringify(await response.json())).toContain("the provided certificate is not a host certificate")
	})

	it("should revoke a host certificate and include it in the host KRL", async () => {
		const key = ecdsaKey.host()
		const issued = await issue(ca, "host", key, ["revoked_host"])
		expect(issued.status).toBe(200)
		const { certificate } = CertificateResponse.parse(await issued.json())
		const serial = listCertificate(Buffer.from(certificate, "base64").toString()).serial

		// a host certificate cannot be revoked through the user endpoint
		expect((await revoke(ca, "user", serial, key)).status).toBe(404)

		const response = await revoke(ca, "host", serial, key)
		expect(response.status).toBe(200)
		expect(await response.json()).toEqual({ revoked_at: expect.any(String) })

		// earlier tests also revoke host certificates, as renewal revokes the
		// certificate that was renewed
		const revoked = (sqlite.prepare("SELECT serial FROM certificates WHERE certificate_type = 1 AND revoked_at NOTNULL ORDER BY id").all() as { serial: string }[])
			.map((row) => BigInt(row.serial))
		expect(revoked).toContain(serial)

		const { krl, version, generatedAt } = await getKrl(ca, "host")
		expect(krl).toEqual(Buffer.from(new KRLBuilder(await priv(ecdsaKey.ca())).addSerials(revoked).generate(version, "", generatedAt)))
	})

	it("should not serve endpoints for an unknown certificate type", async () => {
		expect((await ca.fetch(new Request("http://example.com/api/v4/other/krl"))).status).toBe(404)
		expect((await revoke(ca, "other", 1n, ecdsaKey.user())).status).toBe(404)
	})

	it("should increment the KRL version only when a certificate is revoked", async () => {
		const { version } = await getKrl(ca)
		expect((await getKrl(ca)).version).toBe(version)

		const key = ecdsaKey.user()
		const serial = await requestUserCertificate(ca, key)
		// issuing a certificate does not change the KRL
		expect((await getKrl(ca)).version).toBe(version)

		const response = await revoke(ca, "user", serial, key)
		expect(response.status).toBe(200)

		expect((await getKrl(ca)).version).toBe(version + 1n)
		expect((await getKrl(ca)).version).toBe(version + 1n)
	})

	it("should increment the KRL version when a revoked certificate leaves the KRL", async () => {
		const { version } = await getKrl(ca)

		// a revoked certificate is included until 24 hours after it expires, but
		// is kept in the database until cleanup
		sqlite.prepare("UPDATE certificates SET valid_before = ? WHERE revoked_at NOTNULL AND certificate_type = 0")
			.run(new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString())

		const { krl, version: next, generatedAt } = await getKrl(ca)
		expect(next).toBe(version + 1n)
		expect(krl).toEqual(Buffer.from(new KRLBuilder(await priv(ecdsaKey.ca())).generate(next, "", generatedAt)))
	})

	it("should remove expired certificates on cleanup", async () => {
		sqlite.prepare("INSERT INTO certificates (serial, key_id, principals, valid_after, valid_before) VALUES (?, ?, ?, ?, ?)")
			.run("1", "expired", "ssh-admin", "2000-01-01T00:00:00.000Z", "2000-01-02T00:00:00.000Z")
		const before = sqlite.prepare("SELECT count(*) AS n FROM certificates").get()?.n

		await ca.cleanup()

		expect(sqlite.prepare("SELECT serial FROM certificates WHERE serial = '1'").all()).toEqual([])
		expect(sqlite.prepare("SELECT count(*) AS n FROM certificates").get()?.n).toBe(Number(before) - 1)
	})
})

describe("running on Node.js with a node:sqlite database file", () => {
	it("should keep certificates and the schema across restarts", async () => {
		const dir = mkdtempSync(join(tmpdir(), "ssh-ca-db-"))
		const path = join(dir, "ssh-ca.sqlite")

		try {
			const first = new DatabaseSync(path)
			const serial = await requestUserCertificate(caFor(first), ecdsaKey.user())
			first.close()

			const second = new DatabaseSync(path)
			try {
				await requestUserCertificate(caFor(second), ecdsaKey.user())

				expect(second.prepare("SELECT count(*) AS n FROM migrations").get()).toEqual({ n: 6 })
				expect(second.prepare("SELECT serial FROM certificates WHERE serial = ?").all(`${serial}`)).toHaveLength(1)
			} finally {
				second.close()
			}
		} finally {
			rmSync(dir, { recursive: true, force: true })
		}
	})
})
