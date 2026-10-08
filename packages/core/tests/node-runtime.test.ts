import { describe, it, expect, beforeAll, afterAll } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import sshpk from "sshpk"
import { z } from "zod"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { KRLBuilder } from "../src/krl.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof } from "./helpers/proof.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const email = "user@example.com"
const claims = { sub: "user123", email }

const CertificateResponse = z.object({ certificate: z.string() })
const KrlResponse = z.object({ krl: z.string(), signature: z.string() })

const caFor = (sqlite: DatabaseSync): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(sqlite),
	PRIVATE_KEY: secretFromString(ecdsaKey.ca().toString("openssh")),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
}))

const post = async (ca: SshCa, path: string, body: unknown, authorization?: string): Promise<Response> => {
	const headers = new Headers({ "Content-Type": "application/json" })
	if (authorization !== undefined) {
		headers.set("Authorization", authorization)
	}
	return await ca.fetch(new Request(`http://example.com${path}`, { method: "POST", headers, body: JSON.stringify(body) }))
}

const publicKey = (key: sshpk.PrivateKey): string => Buffer.from(key.toPublic().toString("ssh")).toString("base64")

// request a certificate and return its serial
const requestUserCertificate = async (ca: SshCa, key: sshpk.PrivateKey): Promise<bigint> => {
	const response = await post(ca, "/api/v3/user/certificate", {
		public_key: publicKey(key),
		proof: generateProof(key),
		identity: await getIdentityToken(claims),
	}, await getAccessToken(claims))
	expect(response.status).toBe(200)

	const { certificate } = CertificateResponse.parse(await response.json())
	return sshpk.parseCertificate(Buffer.from(certificate, "base64"), "openssh").serial.readBigUInt64BE(0)
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

		expect(sqlite.prepare("SELECT name FROM migrations").all()).toEqual([{ name: "0001_initial_schema" }])
		expect(sqlite.prepare("SELECT key_id, principals, certificate_type, public_key, revoked_at FROM certificates WHERE serial = ?").all(`${serial}`)).toEqual([{
			key_id: email,
			principals: "UID=ssh-admin",
			certificate_type: 0,
			public_key: expect.stringContaining(key.toPublic().toString("ssh").split(" ").slice(0, 2).join(" ")),
			revoked_at: null,
		}])
	})

	it("should only apply migrations once", async () => {
		await requestUserCertificate(ca, ecdsaKey.user())

		expect(sqlite.prepare("SELECT count(*) AS n FROM migrations").get()).toEqual({ n: 1 })
	})

	it("should record issued host certificates", async () => {
		const key = ecdsaKey.host()
		const response = await post(ca, "/api/v3/host/certificate", {
			public_key: publicKey(key),
			proof: generateProof(key),
			identity: await getIdentityToken(claims),
			principals: ["test_host"],
		}, await getAccessToken(claims))
		expect(response.status).toBe(200)

		expect(sqlite.prepare("SELECT key_id, certificate_type FROM certificates WHERE certificate_type = 1").all()).toEqual([
			{ key_id: "host_test_host", certificate_type: 1 },
		])
	})

	it("should revoke a certificate and include it in the KRL", async () => {
		const key = ecdsaKey.user()
		const serial = await requestUserCertificate(ca, key)
		const revoke = { serial: `${serial}`, public_key: publicKey(key), proof: generateProof(key) }

		const response = await post(ca, "/api/v3/user/revoke", revoke)
		expect(response.status).toBe(200)
		expect(await response.json()).toEqual({ revoked_at: expect.any(String) })

		// a second revocation conflicts with the first
		expect((await post(ca, "/api/v3/user/revoke", { ...revoke, proof: generateProof(key) })).status).toBe(409)

		const krlResponse = await ca.fetch(new Request("http://example.com/api/v3/user/krl"))
		expect(krlResponse.status).toBe(200)
		const { krl } = KrlResponse.parse(await krlResponse.json())
		const expected = new KRLBuilder(ecdsaKey.ca()).addSerials([serial]).generate()
		expect(Buffer.from(krl, "base64")).toEqual(Buffer.from(expected))
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

				expect(second.prepare("SELECT count(*) AS n FROM migrations").get()).toEqual({ n: 1 })
				expect(second.prepare("SELECT serial FROM certificates WHERE serial = ?").all(`${serial}`)).toHaveLength(1)
			} finally {
				second.close()
			}
		} finally {
			rmSync(dir, { recursive: true, force: true })
		}
	})
})
