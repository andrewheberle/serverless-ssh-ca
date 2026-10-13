import { env, exports } from "cloudflare:workers"
import {
	adminSecretsStore,
	// @ts-ignore: this import errors but is fine in tests
} from "cloudflare:test"
import { describe, it, expect } from "vitest"

// an Ed25519 CA key in PKCS#8 format, as created by openssl genpkey, must be
// imported by the WebCrypto of the Workers runtime
const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC46HkVY/bKGJu5jNA1nYgR9RYc4GmyRi14c5SJRelvt
-----END PRIVATE KEY-----
`
const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1JQHS0+pLo8MMOcLJ8L7gDoKTy7y3y2djZkEUOyxza"

const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKey)

describe("Ed25519 CA key in PKCS#8 format", () => {
	it("GET /api/v3/ca responds with the public key", async () => {
		const response = await exports.default.fetch("http://example.com/api/v3/ca")

		expect(response.status).toBe(200)
		expect((await response.text()).trim()).toBe(`${publicKey} ${env.ISSUER_DN}`)
	})

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
