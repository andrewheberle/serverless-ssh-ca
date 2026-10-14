import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "../src/index.js"
import { fromNodeSqlite } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { failingCertificateWrites, hostCertificate } from "./helpers/certificate.js"
import { MockSecretStore } from "./helpers/secret.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof } from "./helpers/proof.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// every attempt to record a certificate fails, but nothing is revoked, so
// renewals get as far as recording the certificate
const email = "user@example.com"
const ca = createSshCa(makeEnv({
	DB: failingCertificateWrites(fromNodeSqlite(new DatabaseSync(":memory:"))),
	PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
}))

const post = async (path: string, body: unknown, authorization?: string): Promise<Response> => {
	const headers = new Headers({ "Content-Type": "application/json" })
	if (authorization !== undefined) {
		headers.set("Authorization", authorization)
	}
	return await ca.fetch(new Request(`http://example.com${path}`, { method: "POST", headers, body: JSON.stringify(body) }))
}

const expectRecordingFailure = async (response: Response): Promise<void> => {
	expect(response.status).toBe(500)
	const body = await response.json()
	// the certificate must not be returned if it could not be recorded
	expect(body).not.toHaveProperty("certificate")
	expect(body).toMatchObject({ success: false, errors: [{ code: 7009 }] })
}

describe("certificate issuance when the database write fails", () => {
	const claims = { sub: "user123", email: email }

	it("user certificate request responds with a 500", async () => {
		const key = ecdsaKey.user()
		const response = await post("/api/v3/user/certificate", {
			public_key: Buffer.from(key.publicKey).toString("base64"),
			proof: generateProof(key),
			identity: await getIdentityToken(claims),
		}, await getAccessToken(claims))

		await expectRecordingFailure(response)
	})

	it("host certificate request responds with a 500", async () => {
		const key = ecdsaKey.host()
		const response = await post("/api/v3/host/certificate", {
			public_key: Buffer.from(key.publicKey).toString("base64"),
			proof: generateProof(key),
			identity: await getIdentityToken(claims),
			principals: ["test_host"],
		}, await getAccessToken(claims))

		await expectRecordingFailure(response)
	})

	it("host certificate renewal responds with a 500", async () => {
		const key = ecdsaKey.host()
		const certificate = hostCertificate(ecdsaKey.ca(), key)
		const response = await post("/api/v3/host/renew", {
			certificate: Buffer.from(certificate.toString()).toString("base64"),
			public_key: Buffer.from(key.publicKey).toString("base64"),
			proof: generateProof(key),
		})

		await expectRecordingFailure(response)
	})
})
