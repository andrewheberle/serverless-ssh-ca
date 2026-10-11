import { describe, expect, it } from "vitest"
import { signCertificate, SshCertificate, type CertificateFields } from "../src/ssh/certificate.js"
import { decodePublicKey, SSHUnsignedMpint } from "../src/ssh/encoding.js"
import { PublicKey } from "../src/ssh/keys.js"
import { createSigner } from "../src/ssh/signer.js"
import { createSignedCertificate, createSignedHostCertificate, CertificateError } from "../src/certificate.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { fingerprint, generateKey, listCertificate, sshKeygen, withTempDir } from "./helpers/ssh-keygen.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as rsaKey } from "./keys/rsa.js"
import type { TestKey } from "./keys/types.js"
import { priv, pub } from "./helpers/keys.js"
import { writeFileSync } from "node:fs"
import { join } from "node:path"

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64")

const cas: [string, () => TestKey, string][] = [
	["Ed25519", () => ed25519Key.ca(), "ssh-ed25519"],
	["ECDSA nistp256", () => ecdsaKey.ca(), "ecdsa-sha2-nistp256"],
	["ECDSA nistp384", () => generateKey("ecdsa", 384), "ecdsa-sha2-nistp384"],
	["ECDSA nistp521", () => generateKey("ecdsa", 521), "ecdsa-sha2-nistp521"],
]

const subjects: [string, () => TestKey][] = [
	["RSA", () => rsaKey.user()],
	["ECDSA", () => ecdsaKey.user()],
	["Ed25519", () => ed25519Key.user()],
]

const fieldsFor = (key: TestKey, overrides: Partial<CertificateFields> = {}): CertificateFields => ({
	kind: "user",
	publicKey: pub(key),
	serial: 12345678901234567890n,
	keyId: "user@example.com",
	principals: ["alice", "bob"],
	validAfter: new Date("2026-01-02T03:04:05Z"),
	validBefore: new Date("2026-01-03T03:04:05Z"),
	extensions: ["permit-pty", "permit-X11-forwarding"],
	...overrides,
})

describe("signCertificate", () => {
	describe.each(cas)("with an %s CA key", (_, caKey, signatureAlgorithm) => {
		const ca = caKey()

		it.each(subjects)("should be accepted by ssh-keygen for a %s user key", async (_, subjectKey) => {
			const fields = fieldsFor(subjectKey())
			const certificate = await signCertificate(fields, await createSigner(priv(ca)))

			expect(listCertificate(certificate.toString())).toEqual({
				type: certificate.type,
				kind: "user",
				publicKey: fingerprint(subjectKey().publicKey),
				signingCa: fingerprint(ca.publicKey),
				signatureAlgorithm,
				keyId: "user@example.com",
				serial: 12345678901234567890n,
				validAfter: fields.validAfter,
				validBefore: fields.validBefore,
				principals: ["alice", "bob"],
				criticalOptions: [],
				// extensions are written in lexical order
				extensions: ["permit-X11-forwarding", "permit-pty"],
			})
		})

		it("should be accepted by ssh-keygen for a host key", async () => {
			const certificate = await signCertificate(fieldsFor(ed25519Key.host(), {
				kind: "host",
				keyId: "host_host.example.com",
				principals: ["host.example.com"],
				extensions: [],
			}), await createSigner(priv(ca)))

			expect(listCertificate(certificate.toString())).toMatchObject({
				type: certificate.type,
				kind: "host",
				signingCa: fingerprint(ca.publicKey),
				principals: ["host.example.com"],
				extensions: [],
			})
		})
	})

	it("should not be accepted by ssh-keygen with a modified signature", async () => {
		const certificate = await signCertificate(fieldsFor(ed25519Key.user()), await createSigner(priv(ed25519Key.ca())))
		const bytes = new Uint8Array(certificate.bytes)
		bytes[bytes.length - 1]! ^= 0x01

		const status = withTempDir((dir) => {
			const file = join(dir, "key-cert.pub")
			writeFileSync(file, `${certificate.type} ${toBase64(bytes)}\n`)

			return sshKeygen("-L", "-f", file).status
		})
		expect(status).not.toBe(0)
	})

	it("should decode the fields it was signed with", async () => {
		const key = ecdsaKey.user()
		const fields = fieldsFor(key, { extensions: ["permit-pty", "permit-agent-forwarding", "permit-pty"] })
		const certificate = await signCertificate(fields, await createSigner(priv(ed25519Key.ca())))
		const decoded = new SshCertificate(certificate.bytes)

		expect(decoded.type).toBe("ecdsa-sha2-nistp256-cert-v01@openssh.com")
		expect(decoded.kind).toBe("user")
		expect(decoded.publicKey.equals(fields.publicKey)).toBe(true)
		expect(decoded.publicKey.toString()).toBe(key.publicKey.split(" ").slice(0, 2).join(" "))
		expect(decoded.serial).toBe(fields.serial)
		expect(decoded.keyId).toBe(fields.keyId)
		expect(decoded.principals).toEqual(fields.principals)
		expect(decoded.validAfter).toEqual(fields.validAfter)
		expect(decoded.validBefore).toEqual(fields.validBefore)
		// in lexical order without duplicates
		expect(decoded.extensions).toEqual(["permit-agent-forwarding", "permit-pty"])
		expect(new PublicKey(decoded.signatureKey).equals(pub(ed25519Key.ca()))).toBe(true)
		expect(decoded.toString()).toBe(certificate.toString())
	})

	it("should use a different nonce for each certificate", async () => {
		const signer = await createSigner(priv(ed25519Key.ca()))
		const first = await signCertificate(fieldsFor(ed25519Key.user()), signer)
		const second = await signCertificate(fieldsFor(ed25519Key.user()), signer)

		expect(first.toString()).not.toBe(second.toString())
	})
})

describe("issued certificates", () => {
	const env = makeEnv({ PRIVATE_KEY: new MockSecretStore(ed25519Key.ca().privateKey) })

	it("should not issue a user certificate without principals", async () => {
		const noPrincipals = makeEnv({ PRIVATE_KEY: new MockSecretStore(ed25519Key.ca().privateKey), SSH_CERTIFICATE_PRINCIPALS: "" })

		await expect(createSignedCertificate(noPrincipals, "user@example.com", pub(ed25519Key.user())))
			.rejects.toBeInstanceOf(CertificateError)
	})

	it("should not issue a host certificate without principals", async () => {
		await expect(createSignedHostCertificate(env, pub(ed25519Key.host()), { principals: [] }))
			.rejects.toBeInstanceOf(CertificateError)
	})

	it("should be valid from the current second for the requested lifetime", async () => {
		const before = Date.now()
		const certificate = await createSignedCertificate(env, "user@example.com", pub(ed25519Key.user()), { lifetime: 3600 })

		expect(certificate.validAfter.getTime()).toBeLessThanOrEqual(Date.now())
		expect(certificate.validAfter.getTime()).toBeGreaterThan(before - 1000)
		expect(certificate.validBefore.getTime() - certificate.validAfter.getTime()).toBe(3600 * 1000)
	})

	it("should use the email address as the key ID of a user certificate", async () => {
		const certificate = await createSignedCertificate(env, "user@example.com", pub(ed25519Key.user()))

		expect(certificate.keyId).toBe("user@example.com")
	})

	it("should use the first principal as the key ID of a host certificate", async () => {
		const certificate = await createSignedHostCertificate(env, pub(ed25519Key.host()), { principals: ["first.example.com", "second.example.com"] })

		expect(certificate.keyId).toBe("host_first.example.com")
		expect(certificate.principals).toEqual(["first.example.com", "second.example.com"])
	})
})

describe("SSHUnsignedMpint", () => {
	it.each([
		["zero", [], [0, 0, 0, 0]],
		["a value without the high bit set", [0x7f, 0x01], [0, 0, 0, 2, 0x7f, 0x01]],
		["a value with the high bit set", [0x80, 0x01], [0, 0, 0, 3, 0x00, 0x80, 0x01]],
		["a value with leading zero bytes", [0x00, 0x00, 0x7f], [0, 0, 0, 1, 0x7f]],
		["a value with leading zero bytes and the high bit set", [0x00, 0xff], [0, 0, 0, 2, 0x00, 0xff]],
	])("should encode %s", (_, value, encoded) => {
		expect(Array.from(SSHUnsignedMpint.encode(new Uint8Array(value)))).toEqual(encoded)
	})

	it("should decode without the sign byte", () => {
		expect(Array.from(SSHUnsignedMpint.decode(new Uint8Array([0, 0, 0, 3, 0x00, 0x80, 0x01])))).toEqual([0x80, 0x01])
	})
})

describe("decodePublicKey", () => {
	it.each(subjects)("should decode a %s public key", (_, key) => {
		const blob = pub(key()).blob
		const { type } = decodePublicKey(blob)

		expect(type).toBe(key().publicKey.split(" ")[0])
	})

	it("should reject an unsupported key type", () => {
		const blob = new Uint8Array([0, 0, 0, 7, ...new TextEncoder().encode("ssh-dss"), 0, 0, 0, 0])

		expect(() => decodePublicKey(blob)).toThrow("unsupported public key type: ssh-dss")
	})
})
