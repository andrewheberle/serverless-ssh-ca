import { describe, expect, it } from "vitest"
import * as P from "micro-packed"
import type { SshCertificate } from "../src/ssh/certificate.js"
import { createSignedCertificate, createSignedHostCertificate } from "../src/certificate.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { fingerprint, generateKey, listCertificate } from "./helpers/ssh-keygen.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import type { TestKey } from "./keys/types.js"
import { pub } from "./helpers/keys.js"

// the size in bits and the size in bytes of r for each curve
const curves = [
	["nistp256", 256, 32],
	["nistp384", 384, 48],
	["nistp521", 521, 66],
] as const

// an ECDSA signature: string algorithm, string (mpint r, mpint s)
const EcdsaSignature = P.struct({
	algorithm: P.string(P.U32BE),
	signature: P.prefix(P.U32BE, P.struct({ r: P.bytes(P.U32BE), s: P.bytes(P.U32BE) })),
})

// whether the r value of the certificate signature has leading zero bytes,
// which is when sshpk could not work out the curve from its length
const hasShortR = (certificate: SshCertificate, size: number): boolean => {
	const { r } = EcdsaSignature.decode(certificate.signature).signature
	const value = BigInt(`0x${Buffer.from(r).toString("hex") || "0"}`)

	return value < 1n << BigInt((size - 1) * 8)
}

// ssh-keygen verifies the signature, and must report the curve of the CA key
const expectValid = (certificate: SshCertificate, ca: TestKey, curve: string) => {
	const listed = listCertificate(certificate.toString())
	expect(listed.signingCa).toBe(fingerprint(ca.publicKey))
	expect(listed.signatureAlgorithm).toBe(`ecdsa-sha2-${curve}`)
}

describe("certificates signed by an ECDSA CA", () => {
	const publicKey = pub(ecdsaKey.user())

	describe.each(curves)("with a %s CA key", (curve, bits, size) => {
		const ca = generateKey("ecdsa", bits)
		const env = makeEnv({ PRIVATE_KEY: new MockSecretStore(ca.privateKey) })

		it.each([
			["user", () => createSignedCertificate(env, "user@example.com", publicKey)],
			["host", () => createSignedHostCertificate(env, publicKey, { principals: ["host.example.com"] })],
		])("should be valid for a %s certificate whose signature has a short r value", async (_, create) => {
			// about 1 in 256 signatures for nistp256 and nistp384, so the chance
			// of none in this many attempts is negligible
			for (let attempt = 0; attempt < 5000; attempt++) {
				const certificate = await create()
				if (hasShortR(certificate, size)) {
					expectValid(certificate, ca, curve)
					return
				}
			}

			expect.fail("no signature with a short r value was made")
		}, 60000)

		it("should be valid for a certificate whose signature has a full length r value", async () => {
			for (let attempt = 0; attempt < 100; attempt++) {
				const certificate = await createSignedCertificate(env, "user@example.com", publicKey)
				if (!hasShortR(certificate, size)) {
					expectValid(certificate, ca, curve)
					return
				}
			}

			expect.fail("no signature with a full length r value was made")
		})
	})
})
