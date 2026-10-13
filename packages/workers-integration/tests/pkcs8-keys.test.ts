import { env } from "cloudflare:workers"
import { createSshCa } from "@andrewheberle/serverless-ssh-ca"
import { describe, it, expect } from "vitest"

// CA keys in PKCS#8 format, as created by openssl genpkey, must be imported by
// the WebCrypto of the Workers runtime. The runtime imports an ECDSA key as
// Ed25519 without checking its type and only fails when it is exported, which
// Node does not, so this must be tested under workerd.
const keys = [
	{
		name: "Ed25519",
		privateKey: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC46HkVY/bKGJu5jNA1nYgR9RYc4GmyRi14c5SJRelvt
-----END PRIVATE KEY-----
`,
		publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1JQHS0+pLo8MMOcLJ8L7gDoKTy7y3y2djZkEUOyxza",
	},
	{
		name: "ECDSA P-256",
		privateKey: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRYEhWkgl6Ju7fBK/
/8DcQMSr7qq+P7NcJQ/ZpQU5huShRANCAARRpRGFAWJ3ZlIUCfShnTG4873CvJxF
R75mVMd6zxFcWdUtwtJAyqF2pJFhJTOAxo6n0XTep/KTC28amGpYuRfN
-----END PRIVATE KEY-----
`,
		publicKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFGlEYUBYndmUhQJ9KGdMbjzvcK8nEVHvmZUx3rPEVxZ1S3C0kDKoXakkWElM4DGjqfRdN6n8pMLbxqYali5F80=",
	},
	{
		// the same key as above, without the optional embedded public key
		name: "ECDSA P-256 without the public key",
		privateKey: `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBFgSFaSCXom7t8Er//
wNxAxKvuqr4/s1wlD9mlBTmG5A==
-----END PRIVATE KEY-----
`,
		publicKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFGlEYUBYndmUhQJ9KGdMbjzvcK8nEVHvmZUx3rPEVxZ1S3C0kDKoXakkWElM4DGjqfRdN6n8pMLbxqYali5F80=",
	},
	{
		name: "ECDSA P-384",
		privateKey: `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD8s/4yFPq+46SDLPrt
WiWZUNu9Pk7uMPQmr4hgR+dPyQd20bX6MjdJziPl6YinAMyhZANiAAQ8Y3fBXU5g
2siJ1dBYZwNXKbedYj+Jc058auOnuUtyww++j47X/weBdgyD4SqfaQJVbjQPzM9U
9fy8/mKa8Ww5VeSCZlLp39OvcgM3CIrqpPtRYnqj2jO9B7Rg/ESd//M=
-----END PRIVATE KEY-----
`,
		publicKey: "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBDxjd8FdTmDayInV0FhnA1cpt51iP4lzTnxq46e5S3LDD76Pjtf/B4F2DIPhKp9pAlVuNA/Mz1T1/Lz+YprxbDlV5IJmUunf069yAzcIiuqk+1FieqPaM70HtGD8RJ3/8w==",
	},
	{
		name: "ECDSA P-521",
		privateKey: `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBp/1tmsOu4xvKChjl
D4rezz9jamM6mQiB+5IFFKREj91/nBtFPjEO/Xg4rQ4x9pSwbsLO6cE0UAhfd8aH
wFZvRrWhgYkDgYYABAFVdfIHQFmOlECSDdhSQQ7Rw0OJ88Yp8JLOjlKLzc8eQ7tz
xpB/LHDPuFJiZ5jjc8iEa0xqJyagq5JJ2sS9l1SAsAC+ztciodtrC4VNv/7YprJ+
e6OWg2BnEqq2vpRXlUU8j1An7AS6jOyz8Spdgm/nub49c7CfIinHp/JBh0ff94MN
0A==
-----END PRIVATE KEY-----
`,
		publicKey: "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFVdfIHQFmOlECSDdhSQQ7Rw0OJ88Yp8JLOjlKLzc8eQ7tzxpB/LHDPuFJiZ5jjc8iEa0xqJyagq5JJ2sS9l1SAsAC+ztciodtrC4VNv/7YprJ+e6OWg2BnEqq2vpRXlUU8j1An7AS6jOyz8Spdgm/nub49c7CfIinHp/JBh0ff94MN0A==",
	},
]

describe("CA keys in PKCS#8 format", () => {
	it.each(keys)("GET /api/v4/ca responds with the public key of an $name key", async ({ privateKey, publicKey }) => {
		const ca = createSshCa({ ...env, PRIVATE_KEY: { get: async () => privateKey } })
		const response = await ca.fetch(new Request("http://example.com/api/v4/ca"))

		expect(response.status).toBe(200)
		expect((await response.text()).trim()).toBe(`${publicKey} ${env.ISSUER_DN}`)
	})
})
