import { spawnSync } from "node:child_process"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"
import sshpk from "sshpk"
import type { PrivateKey } from "sshpk"
import { signCertificate, SshCertificate, type CertificateFields } from "../src/ssh/certificate.js"
import { decodePublicKey, SSHUnsignedMpint } from "../src/ssh/encoding.js"
import { createSigner } from "../src/ssh/signer.js"
import { createSignedCertificate, createSignedHostCertificate, CertificateError } from "../src/certificate.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as rsaKey } from "./keys/rsa.js"

// returns the output of ssh-keygen -L, which fails if the certificate does not
// parse or its signature does not verify
const sshKeygenList = (certificate: string): { status: number | null, output: string } => {
	const dir = mkdtempSync(join(tmpdir(), "ssh-cert-"))
	try {
		const file = join(dir, "key-cert.pub")
		writeFileSync(file, `${certificate}\n`)
		const result = spawnSync("ssh-keygen", ["-L", "-f", file])

		return { status: result.status, output: `${result.stdout.toString()}${result.stderr.toString()}` }
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
}

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64")

// ssh-keygen prints times in the local time zone without one, to the second
const sshKeygenTime = (date: Date): string => {
	const pad = (n: number) => `${n}`.padStart(2, "0")

	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

const cas: [string, () => PrivateKey, string][] = [
	["Ed25519", () => ed25519Key.ca(), "ssh-ed25519"],
	["ECDSA nistp256", () => ecdsaKey.ca(), "ecdsa-sha2-nistp256"],
	["ECDSA nistp384", () => sshpk.generatePrivateKey("ecdsa", { curve: "nistp384" }), "ecdsa-sha2-nistp384"],
	["ECDSA nistp521", () => sshpk.generatePrivateKey("ecdsa", { curve: "nistp521" }), "ecdsa-sha2-nistp521"],
]

const subjects: [string, () => PrivateKey, string][] = [
	["RSA", () => rsaKey.user(), "RSA-CERT"],
	["ECDSA", () => ecdsaKey.user(), "ECDSA-CERT"],
	["Ed25519", () => ed25519Key.user(), "ED25519-CERT"],
]

const fieldsFor = (key: PrivateKey, overrides: Partial<CertificateFields> = {}): CertificateFields => ({
	kind: "user",
	publicKey: new Uint8Array(key.toPublic().toBuffer("rfc4253")),
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

		it.each(subjects)("should be accepted by ssh-keygen for a %s user key", async (_, subjectKey, certType) => {
			const fields = fieldsFor(subjectKey())
			const certificate = await signCertificate(fields, await createSigner(ca))

			const { status, output } = sshKeygenList(certificate.toString())
			expect(output).toContain(`Type: ${certificate.type} user certificate`)
			expect(output).toContain(`Public key: ${certType} ${subjectKey().toPublic().fingerprint("sha256").toString()}`)
			expect(output).toContain(`Signing CA: `)
			expect(output).toContain(`${ca.toPublic().fingerprint("sha256").toString()} (using ${signatureAlgorithm})`)
			expect(output).toContain(`Key ID: "user@example.com"`)
			expect(output).toContain(`Serial: 12345678901234567890`)
			expect(output).toContain(`Valid: from ${sshKeygenTime(fields.validAfter)} to ${sshKeygenTime(fields.validBefore)}`)
			expect(output).toMatch(/Principals: \n\s+alice\n\s+bob\n/)
			expect(output).toContain("Critical Options: (none)")
			// extensions are written in lexical order
			expect(output).toMatch(/Extensions: \n\s+permit-X11-forwarding\n\s+permit-pty\n/)
			expect(status).toBe(0)
		})

		it("should be accepted by ssh-keygen for a host key", async () => {
			const certificate = await signCertificate(fieldsFor(ed25519Key.host(), {
				kind: "host",
				keyId: "host_host.example.com",
				principals: ["host.example.com"],
				extensions: [],
			}), await createSigner(ca))

			const { status, output } = sshKeygenList(certificate.toString())
			expect(output).toContain(`Type: ${certificate.type} host certificate`)
			expect(output).toMatch(/Principals: \n\s+host.example.com\n/)
			expect(output).toContain("Extensions: (none)")
			expect(status).toBe(0)
		})

		it("should be verified by sshpk", async () => {
			const certificate = await signCertificate(fieldsFor(ecdsaKey.user()), await createSigner(ca))

			const parsed = sshpk.parseCertificate(Buffer.from(certificate.toString()), "openssh")
			expect(parsed.isSignedByKey(ca.toPublic())).toBe(true)
		})
	})

	it("should not be accepted by ssh-keygen with a modified signature", async () => {
		const certificate = await signCertificate(fieldsFor(ed25519Key.user()), await createSigner(ed25519Key.ca()))
		const bytes = new Uint8Array(certificate.bytes)
		bytes[bytes.length - 1]! ^= 0x01

		expect(sshKeygenList(`${certificate.type} ${toBase64(bytes)}`).status).not.toBe(0)
	})

	it("should decode the fields it was signed with", async () => {
		const key = ecdsaKey.user()
		const fields = fieldsFor(key, { extensions: ["permit-pty", "permit-agent-forwarding", "permit-pty"] })
		const certificate = await signCertificate(fields, await createSigner(ed25519Key.ca()))
		const decoded = new SshCertificate(certificate.bytes)

		expect(decoded.type).toBe("ecdsa-sha2-nistp256-cert-v01@openssh.com")
		expect(decoded.kind).toBe("user")
		expect(decoded.publicKey).toEqual(fields.publicKey)
		expect(decoded.publicKeyString()).toBe(key.toPublic().toString("ssh").split(" ").slice(0, 2).join(" "))
		expect(decoded.serial).toBe(fields.serial)
		expect(decoded.keyId).toBe(fields.keyId)
		expect(decoded.principals).toEqual(fields.principals)
		expect(decoded.validAfter).toEqual(fields.validAfter)
		expect(decoded.validBefore).toEqual(fields.validBefore)
		// in lexical order without duplicates
		expect(decoded.extensions).toEqual(["permit-agent-forwarding", "permit-pty"])
		expect(decoded.signatureKey).toEqual(new Uint8Array(ed25519Key.ca().toPublic().toBuffer("rfc4253")))
		expect(decoded.toString()).toBe(certificate.toString())
	})

	it("should use a different nonce for each certificate", async () => {
		const signer = await createSigner(ed25519Key.ca())
		const first = await signCertificate(fieldsFor(ed25519Key.user()), signer)
		const second = await signCertificate(fieldsFor(ed25519Key.user()), signer)

		expect(first.toString()).not.toBe(second.toString())
	})
})

describe("issued certificates", () => {
	const env = makeEnv({ PRIVATE_KEY: new MockSecretStore(ed25519Key.ca().toString("openssh")) })

	it("should not issue a user certificate without principals", async () => {
		const noPrincipals = makeEnv({ PRIVATE_KEY: new MockSecretStore(ed25519Key.ca().toString("openssh")), SSH_CERTIFICATE_PRINCIPALS: "" })

		await expect(createSignedCertificate(noPrincipals, "user@example.com", ed25519Key.user().toPublic()))
			.rejects.toBeInstanceOf(CertificateError)
	})

	it("should not issue a host certificate without principals", async () => {
		await expect(createSignedHostCertificate(env, ed25519Key.host().toPublic(), { principals: [] }))
			.rejects.toBeInstanceOf(CertificateError)
	})

	it("should be valid from the current second for the requested lifetime", async () => {
		const before = Date.now()
		const certificate = await createSignedCertificate(env, "user@example.com", ed25519Key.user().toPublic(), { lifetime: 3600 })

		expect(certificate.validAfter.getTime()).toBeLessThanOrEqual(Date.now())
		expect(certificate.validAfter.getTime()).toBeGreaterThan(before - 1000)
		expect(certificate.validBefore.getTime() - certificate.validAfter.getTime()).toBe(3600 * 1000)
	})

	it("should use the email address as the key ID of a user certificate", async () => {
		const certificate = await createSignedCertificate(env, "user@example.com", ed25519Key.user().toPublic())

		expect(certificate.keyId).toBe("user@example.com")
	})

	it("should use the first principal as the key ID of a host certificate", async () => {
		const certificate = await createSignedHostCertificate(env, ed25519Key.host().toPublic(), { principals: ["first.example.com", "second.example.com"] })

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
		const blob = new Uint8Array(key().toPublic().toBuffer("rfc4253"))
		const { type } = decodePublicKey(blob)

		expect(type).toBe(key().toPublic().toString("ssh").split(" ")[0])
	})

	it("should reject an unsupported key type", () => {
		const blob = new Uint8Array([0, 0, 0, 7, ...new TextEncoder().encode("ssh-dss"), 0, 0, 0, 0])

		expect(() => decodePublicKey(blob)).toThrow("unsupported public key type: ssh-dss")
	})
})
