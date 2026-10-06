import { describe, it, expect } from "vitest"
import { generatePrivateKey, parsePrivateKey, type PrivateKey } from "sshpk"
import { KRLBuilder } from "../src/krl"
import { verify } from "../src/sshsig"
import { key as ecdsaKey } from "./keys/ecdsa"
import { key as ed25519Key } from "./keys/ed25519"

const namespace = "krl@com.github.serverless-ssh-ca.andrewheberle"

const signAndVerify = async (caKey: PrivateKey): Promise<boolean> => {
	const krl = new KRLBuilder(caKey).addSerials([1n, 2n])
	const bytes = new Uint8Array(krl.generate())
	return await verify(await krl.signature(), bytes, { namespace })
}

// ECDSA CA keys whose private key is shorter than the curve size, which sshpk
// writes to PKCS#8 without the required leading zero bytes
const shortEcdsaKeys: { curve: string, size: number, key: string }[] = [
	{
		curve: "nistp256",
		size: 32,
		key: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSTqJtmbzPJxBeEaaaGnBCJl7wy6NtE
gucGgLu0/H9TdWWhdb1ATAEi7NpIytWqz178Yc4e9R7qCpxykkv4Crw4AAAAmJlKqFWZSq
hVAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJOom2ZvM8nEF4Rp
poacEImXvDLo20SC5waAu7T8f1N1ZaF1vUBMASLs2kjK1arPXvxhzh71HuoKnHKSS/gKvD
gAAAAfIBQ9jXgJRzFedwzXtoCk+XghYBr6kCO2oEihGtZxyQAAAAAB
-----END OPENSSH PRIVATE KEY-----
`,
	},
	{
		curve: "nistp384",
		size: 48,
		key: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTbbBWX/NJzq75VGHWNQJlGHA43OV4W
YWzSGVN3hbLT6660+s5Lsop3WeG3+nGp7hpB55TJ+7fcxGoFXrzRy5cdt+r+1gIxlr8W9o
327ZO+rpxhLJ5fgltB7c7XDb6NFSYAAADIVFzx4VRc8eEAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEE22wVl/zSc6u+VRh1jUCZRhwONzleFmFs0hlTd4Wy0+
uutPrOS7KKd1nht/pxqe4aQeeUyfu33MRqBV680cuXHbfq/tYCMZa/FvaN9u2Tvq6cYSye
X4JbQe3O1w2+jRUmAAAAMACKte4SuHu5WQXjhfxewKIXVMxJT4OLpzjje0hd885k9ZVg8L
IbCMXdm1eIfOqDtQAAAAA=
-----END OPENSSH PRIVATE KEY-----
`,
	},
	{
		curve: "nistp521",
		size: 66,
		key: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQAmxwB4z4xvHo6x22qQW8gqXLZedxP
xv0MPuJ2eIeC2SrKmKozzQXrPuXwNkA7ak0/3Db6/M3WQEgTJutRz+RiABsBmouo3Pn3XF
hbURUin00A5ChAj/fvLEQ4JSV6QS15xetE9FA1G0YsJNbqHZ7U+zFtQzg9ne2lsmCRo+wg
QYlPs5YAAAEAIfw0ryH8NK8AAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAJscAeM+Mbx6OsdtqkFvIKly2XncT8b9DD7idniHgtkqypiqM80F6z7l8DZAO2pN
P9w2+vzN1kBIEybrUc/kYgAbAZqLqNz591xYW1EVIp9NAOQoQI/37yxEOCUlekEtecXrRP
RQNRtGLCTW6h2e1PsxbUM4PZ3tpbJgkaPsIEGJT7OWAAAAQgCJFNndYKQvGQlm6fTBGcMD
UpekFqxBDdqrBaePlCRSVbcA7dChkfZ/AfSZYyu9jfNlPwk4viJeWzxsKY80ABhXZQAAAA
ABAg==
-----END OPENSSH PRIVATE KEY-----
`,
	},
]

describe("KRLBuilder signature", () => {
	it.each([
		["ECDSA CA", ecdsaKey.ca()],
		["Ed25519 CA", ed25519Key.ca()],
		["Ed25519 CA with a leading zero seed byte", ed25519Key.leadingZeroCa()],
	] as [string, PrivateKey][])("%s should produce a valid signature", async (_, caKey) => {
		expect(await signAndVerify(caKey)).toBe(true)
	})

	it.each(shortEcdsaKeys)("ECDSA $curve CA with a short private key should produce a valid signature", async ({ key, size }) => {
		const caKey = parsePrivateKey(key)

		// guards against the fixture being replaced with an ordinary key
		const d = caKey.parts.find((p) => p.name === "d")?.data ?? []
		const start = d.findIndex((b) => b !== 0)
		expect(d.length - start).toBeLessThan(size)

		expect(await signAndVerify(caKey)).toBe(true)
	})

	// covers every encoding sshpk produces for the private key: short, full
	// width and with a leading sign byte
	it.each(["nistp256", "nistp384", "nistp521"] as const)("should sign with generated ECDSA %s CA keys", async (curve) => {
		const failures: string[] = []
		for (let i = 0; i < 100; i++) {
			const caKey = generatePrivateKey("ecdsa", { curve })
			if (!(await signAndVerify(caKey))) {
				failures.push(caKey.toString("openssh"))
			}
		}
		expect(failures).toEqual([])
	}, 60000)

	it("leading zero seed fixture should match the problem pattern", () => {
		// guards against the fixture being replaced with an ordinary key
		const seed = ed25519Key.leadingZeroCa().parts.find((p) => p.name === "k")?.data
		expect(seed?.[0]).toBe(0x00)
		expect(seed?.[1]).toBeLessThan(0x80)
	})
})
