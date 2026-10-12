import { describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateRequestProof } from "./helpers/proof.js"
import { listCertificate } from "./helpers/ssh-keygen.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// report every certificate as revocable, as a request that checked the status
// before another request revoked the certificate would see it
vi.mock("../src/db", async (importOriginal) => {
	const original = await importOriginal<typeof import("../src/db/index.js")>()
	return {
		...original,
		revocationStatus: vi.fn(async () => original.RevocationStatus.Revokable),
	}
})

describe("revoking a certificate revoked by another request", () => {
	it("should respond with a 409 and keep the first revocation time", async () => {
		const sqlite = new DatabaseSync(":memory:")
		const ca = createSshCa(makeEnv({
			DB: fromNodeSqlite(sqlite),
			PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
		}))
		const key = ecdsaKey.user()
		const claims = { sub: "user123", email: "user@example.com" }

		const issued = await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": await getAccessToken(claims),
				"Proof-Of-Possession": generateRequestProof(key, "POST", "/api/v4/user/certificates"),
			},
			body: JSON.stringify({ public_key: Buffer.from(key.publicKey).toString("base64"), identity: await getIdentityToken(claims) }),
		}))
		expect(issued.status).toBe(200)
		const { certificate } = await issued.json() as { certificate: string }
		const serial = listCertificate(Buffer.from(certificate, "base64").toString()).serial

		const revoke = async (): Promise<Response> => await ca.fetch(new Request(`http://example.com/api/v4/user/certificates/${serial}`, {
			method: "DELETE",
			headers: { "Proof-Of-Possession": generateRequestProof(key, "DELETE", `/api/v4/user/certificates/${serial}`) },
		}))

		const first = await revoke()
		expect(first.status).toBe(200)
		const { revoked_at } = await first.json() as { revoked_at: string }

		const second = await revoke()
		expect(second.status).toBe(409)
		expect(sqlite.prepare("SELECT revoked_at FROM certificates WHERE serial = ?").get(`${serial}`)).toEqual({ revoked_at })
	})
})
