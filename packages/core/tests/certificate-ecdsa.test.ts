import { spawnSync } from "node:child_process"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"
import sshpk from "sshpk"
import type { PrivateKey } from "sshpk"
import type { SshCertificate } from "../src/ssh/certificate.js"
import { createSignedCertificate, createSignedHostCertificate } from "../src/certificate.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// the size in bytes of r for each curve
const curves = [
	["nistp256", 32],
	["nistp384", 48],
	["nistp521", 66],
] as const

// whether the r value of the certificate signature is shorter than the size
// of the curve, which is when sshpk cannot work out the curve from its length
const hasShortR = (certificate: SshCertificate, size: number): boolean => {
	const r = sshpk.parseCertificate(Buffer.from(certificate.toString()), "openssh").signatures.openssh!.signature.part.r.data
	const value = BigInt(`0x${r.toString("hex") || "0"}`)

	return value < 1n << BigInt((size - 1) * 8)
}

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

const expectValid = (certificate: SshCertificate, ca: PrivateKey) => {
	const text = certificate.toString()

	const parsed = sshpk.parseCertificate(Buffer.from(text), "openssh")
	expect(parsed.isSignedByKey(ca.toPublic())).toBe(true)

	const { status, output } = sshKeygenList(text)
	expect(output).toContain(`(using ecdsa-sha2-${ca.curve})`)
	expect(status).toBe(0)
}

describe("certificates signed by an ECDSA CA", () => {
	const publicKey = ecdsaKey.user().toPublic()

	describe.each(curves)("with a %s CA key", (curve, size) => {
		const ca = sshpk.generatePrivateKey("ecdsa", { curve })
		const env = makeEnv({ PRIVATE_KEY: new MockSecretStore(ca.toString("openssh")) })

		it.each([
			["user", () => createSignedCertificate(env, "user@example.com", publicKey)],
			["host", () => createSignedHostCertificate(env, publicKey, { principals: ["host.example.com"] })],
		])("should be valid for a %s certificate whose signature has a short r value", async (_, create) => {
			// about 1 in 256 signatures for nistp256 and nistp384, so the chance
			// of none in this many attempts is negligible
			for (let attempt = 0; attempt < 5000; attempt++) {
				const certificate = await create()
				if (hasShortR(certificate, size)) {
					expectValid(certificate, ca)
					return
				}
			}

			expect.fail("no signature with a short r value was made")
		}, 60000)

		it("should be valid for a certificate whose signature has a full length r value", async () => {
			for (let attempt = 0; attempt < 100; attempt++) {
				const certificate = await createSignedCertificate(env, "user@example.com", publicKey)
				if (!hasShortR(certificate, size)) {
					expectValid(certificate, ca)
					return
				}
			}

			expect.fail("no signature with a full length r value was made")
		})
	})
})
