import { describe, it, expect } from "vitest"
import { base64urlnopad } from "@scure/base"
import { KRLBuilder } from "../src/krl.js"
import { generateKey, isRevoked, testKey, listKrl, signCertificate, verifySignature, fingerprint } from "./helpers/ssh-keygen.js"
import type { TestKey } from "./keys/types.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { priv } from "./helpers/keys.js"

const namespace = "krl@com.github.serverless-ssh-ca.andrewheberle"

// the version and generated date from a KRL header, after the magic and format version
const header = (krl: ArrayBuffer): { version: bigint, generatedDate: bigint } => {
	const view = new DataView(krl)
	return { version: view.getBigUint64(12, false), generatedDate: view.getBigUint64(20, false) }
}

// signs a KRL and verifies the signature with ssh-keygen
const signAndVerify = async (caKey: TestKey): Promise<boolean> => {
	const krl = new KRLBuilder(await priv(caKey)).addSerials([1n, 2n])
	const bytes = new Uint8Array(krl.generate())
	return verifySignature(caKey.publicKey, namespace, bytes, await krl.signature())
}

// the private value of a CA key as WebCrypto is given it
const privateValue = async (key: TestKey): Promise<Uint8Array> => base64urlnopad.decode((await priv(key)).jwk.d!)

// ECDSA CA keys whose private key is shorter than the curve size, which
// WebCrypto requires to be padded with leading zero bytes
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
	] as [string, TestKey][])("%s should produce a valid signature", async (_, caKey) => {
		expect(await signAndVerify(caKey)).toBe(true)
	})

	it.each(shortEcdsaKeys)("ECDSA $curve CA with a short private key should produce a valid signature", async ({ key, size }) => {
		const caKey = testKey(key)

		// guards against the fixture being replaced with an ordinary key
		const d = await privateValue(caKey)
		expect(d.length).toBe(size)
		expect(d[0]).toBe(0)

		expect(await signAndVerify(caKey)).toBe(true)
	})

	// covers every encoding of the private key: short, full width and with a
	// leading sign byte
	it.each([256, 384, 521])("should sign with generated ECDSA P-%i CA keys", async (bits) => {
		const failures: string[] = []
		for (let i = 0; i < 100; i++) {
			const caKey = generateKey("ecdsa", bits)
			if (!(await signAndVerify(caKey))) {
				failures.push(caKey.privateKey)
			}
		}
		expect(failures).toEqual([])
	}, 60000)

	it("leading zero seed fixture should match the problem pattern", async () => {
		// guards against the fixture being replaced with an ordinary key
		const seed = await privateValue(ed25519Key.leadingZeroCa())
		expect(seed[0]).toBe(0x00)
		expect(seed[1]).toBeLessThan(0x80)
	})
})

describe("KRLBuilder generate", () => {
	it("should be read by ssh-keygen", async () => {
		const ca = ecdsaKey.ca()
		const krl = new Uint8Array(new KRLBuilder(await priv(ca)).addSerials([1n, 18446744073709551615n]).addKeyIds(["revoked key"]).generate(7n))

		expect(listKrl(krl)).toEqual({
			version: 7n,
			ca: fingerprint(ca.publicKey),
			serials: [1n, 18446744073709551615n],
			keyIds: ["revoked key"],
		})
	})

	it.each([
		["a revoked serial", 1n, "key", true],
		["a revoked key ID", 3n, "revoked key", true],
		["a serial and key ID that are not revoked", 2n, "key", false],
	])("should be used by ssh-keygen to check a certificate with %s", async (_, serial, keyId, revoked) => {
		const ca = ed25519Key.ca()
		const krl = new Uint8Array(new KRLBuilder(await priv(ca)).addSerials([1n]).addKeyIds(["revoked key"]).generate())
		const certificate = signCertificate(ca, ed25519Key.user().publicKey, { kind: "user", keyId, principals: ["user"], serial })

		expect(isRevoked(krl, certificate)).toBe(revoked)
	})

	it("should not revoke a certificate from another CA", async () => {
		const krl = new Uint8Array(new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n]).generate())
		const certificate = signCertificate(ed25519Key.ca(), ed25519Key.user().publicKey, { kind: "user", keyId: "key", principals: ["user"], serial: 1n })

		expect(isRevoked(krl, certificate)).toBe(false)
	})

	it("should default to version 1", async () => {
		expect(header(new KRLBuilder(await priv(ecdsaKey.ca())).generate()).version).toBe(1n)
	})

	it("should set the version and generated date in the header", async () => {
		const before = BigInt(Math.floor(Date.now() / 1000))
		const krl = new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n]).generate(42n)
		const after = BigInt(Math.floor(Date.now() / 1000))

		const { version, generatedDate } = header(krl)
		expect(version).toBe(42n)
		expect(generatedDate).toBeGreaterThanOrEqual(before)
		expect(generatedDate).toBeLessThanOrEqual(after)
	})
})

describe("KRLBuilder digest", () => {
	it("should not depend on the order serials and key IDs are added in", async () => {
		const a = new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n, 2n, 3n]).addKeyIds(["a", "b"])
		const b = new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([3n]).addKeyIds(["b", "a"]).addSerials([2n, 1n])

		expect(await a.digest()).toBe(await b.digest())
	})

	it("should not change once the KRL is generated", async () => {
		const krl = new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n])
		const digest = await krl.digest()
		krl.generate(5n)

		expect(await krl.digest()).toBe(digest)
	})

	it.each([
		["a serial is added", async () => new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n, 2n, 3n])],
		["a serial is removed", async () => new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n])],
		["a serial is changed", async () => new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n, 4n])],
		["a key ID is added", async () => new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n, 2n]).addKeyIds(["a"])],
		["the CA is changed", async () => new KRLBuilder(await priv(ed25519Key.ca())).addSerials([1n, 2n])],
	] as [string, () => Promise<KRLBuilder>][])("should change when %s", async (_, create) => {
		const krl = await create()
		const base = new KRLBuilder(await priv(ecdsaKey.ca())).addSerials([1n, 2n])

		expect(await krl.digest()).not.toBe(await base.digest())
	})
})
