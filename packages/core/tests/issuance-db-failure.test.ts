import { describe, it, expect, vi } from "vitest"
import { createApp } from "../src/router.js"
import { createSignedHostCertificate } from "../src/certificate.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof } from "./helpers/proof.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// fail every database write, but report nothing as revoked so renewals get
// as far as recording the certificate
vi.mock("../src/db", async (importOriginal) => {
	const original = await importOriginal<typeof import("../src/db/index.js")>()
	return {
		...original,
		isRevoked: vi.fn(async () => false),
		recordCertificate: vi.fn(async () => {
			throw new Error("database unavailable")
		}),
	}
})

const email = "user@example.com"
const env = makeEnv({
	PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().toString("openssh")),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
})
const app = createApp(env)

const post = async (path: string, body: unknown, authorization?: string): Promise<Response> => {
	const headers = new Headers({ "Content-Type": "application/json" })
	if (authorization !== undefined) {
		headers.set("Authorization", authorization)
	}
	return await app.fetch(new Request(`http://example.com${path}`, { method: "POST", headers, body: JSON.stringify(body) }), env)
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
			public_key: Buffer.from(key.toPublic().toString("ssh")).toString("base64"),
			proof: generateProof(key),
			identity: await getIdentityToken(claims),
		}, await getAccessToken(claims))

		await expectRecordingFailure(response)
	})

	it("host certificate request responds with a 500", async () => {
		const key = ecdsaKey.host()
		const response = await post("/api/v3/host/certificate", {
			public_key: Buffer.from(key.toPublic().toString("ssh")).toString("base64"),
			proof: generateProof(key),
			identity: await getIdentityToken(claims),
			principals: ["test_host"],
		}, await getAccessToken(claims))

		await expectRecordingFailure(response)
	})

	it("host certificate renewal responds with a 500", async () => {
		const key = ecdsaKey.host()
		const certificate = await createSignedHostCertificate(env, key.toPublic(), { principals: ["test_host"] })
		const response = await post("/api/v3/host/renew", {
			certificate: Buffer.from(certificate.toString("openssh")).toString("base64"),
			public_key: Buffer.from(key.toPublic().toString("ssh")).toString("base64"),
			proof: generateProof(key),
		})

		await expectRecordingFailure(response)
	})
})
