import { env, exports } from "cloudflare:workers"
import {
	adminSecretsStore,
	// @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect } from "vitest"
import { leadingZeroPrivateKeyString } from "./keys/ed25519"

// an Ed25519 CA key that sshpk cannot export as valid PKCS#8 must still be
// able to sign KRLs
const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(leadingZeroPrivateKeyString)

describe("Ed25519 CA key with a leading zero seed byte", () => {
	it.each([
		"/api/v3/user/krl",
		"/api/v3/host/krl",
	])("GET %s responds with a signed KRL", async (path) => {
		const response = await exports.default.fetch(`http://example.com${path}`)

		expect(response.status).toBe(200)
		expect(await response.json()).toMatchObject({
			krl: expect.any(String),
			signature: expect.stringContaining("-----BEGIN SSH SIGNATURE-----"),
		})
	})
})
