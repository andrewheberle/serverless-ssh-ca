import { describe, it, expect, beforeAll, afterAll } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { z } from "zod"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import type { TestKey } from "./keys/types.js"
import { fingerprint, isRevoked, listCertificate, type ListedCertificate } from "./helpers/ssh-keygen.js"

const email = "user@example.com"
const claims = { sub: "user123", email }

const CertificateResponse = z.object({ certificate: z.string() })
const KrlResponse = z.object({ krl: z.string(), signature: z.string() })
const ErrorResponse = z.object({ errors: z.array(z.object({ message: z.string() })) })

const publicKey = (key: TestKey): string => Buffer.from(key.publicKey).toString("base64")

const request = async (ca: SshCa, method: string, path: string, options: { body?: unknown, proof?: string, authorization?: string } = {}): Promise<Response> => {
	const headers = new Headers()
	if (options.body !== undefined) {
		headers.set("Content-Type", "application/json")
	}
	if (options.proof !== undefined) {
		headers.set("Proof-Of-Possession", options.proof)
	}
	if (options.authorization !== undefined) {
		headers.set("Authorization", options.authorization)
	}

	return await ca.fetch(new Request(`http://example.com${path}`, {
		method,
		headers,
		body: options.body === undefined ? undefined : JSON.stringify(options.body),
	}))
}

const errorMessages = async (response: Response): Promise<string[]> => {
	return ErrorResponse.parse(await response.json()).errors.map((e) => e.message)
}

// an issued certificate, with its fields as shown by ssh-keygen -L, which also
// verifies its signature
type IssuedCertificate = { text: string, listed: ListedCertificate }

const parseCertificate = async (response: Response): Promise<IssuedCertificate> => {
	expect(response.status).toBe(200)
	const text = Buffer.from(CertificateResponse.parse(await response.json()).certificate, "base64").toString()

	return { text, listed: listCertificate(text) }
}

const serialOf = (certificate: IssuedCertificate): bigint => certificate.listed.serial

// the KRL served by the CA
const getKrl = async (ca: SshCa, type: "user" | "host"): Promise<Uint8Array> => {
	const response = await request(ca, "GET", `/api/v4/${type}/krl`)
	expect(response.status).toBe(200)

	return Buffer.from(KrlResponse.parse(await response.json()).krl, "base64")
}

describe("v4 API", () => {
	let sqlite: DatabaseSync
	let ca: SshCa

	const userKey = ecdsaKey.user()
	const otherKey = ed25519Key.host()
	const hostKey = ecdsaKey.host()

	const issueUserCertificate = async (key: TestKey, proof?: string): Promise<Response> => {
		return await request(ca, "POST", "/api/v4/user/certificates", {
			body: {
				public_key: publicKey(key),
				identity: await getIdentityToken(claims),
			},
			proof: proof ?? generateRequestProof(key, "POST", "/api/v4/user/certificates"),
			authorization: await getAccessToken(claims),
		})
	}

	const issueHostCertificate = async (key: TestKey, principals: string[]): Promise<Response> => {
		return await request(ca, "POST", "/api/v4/host/certificates", {
			body: {
				public_key: publicKey(key),
				identity: await getIdentityToken(claims),
				principals,
			},
			proof: generateRequestProof(key, "POST", "/api/v4/host/certificates"),
			authorization: await getAccessToken(claims),
		})
	}

	const revokeCertificate = async (type: "user" | "host", serial: bigint | string, proof: string): Promise<Response> => {
		return await request(ca, "DELETE", `/api/v4/${type}/certificates/${serial}`, { proof })
	}

	const revokeProof = (key: TestKey, type: "user" | "host", serial: bigint | string): string => {
		return generateRequestProof(key, "DELETE", `/api/v4/${type}/certificates/${serial}`)
	}

	beforeAll(() => {
		sqlite = new DatabaseSync(":memory:")
		ca = createSshCa(makeEnv({
			DB: fromNodeSqlite(sqlite),
			PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
			SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
		}))
	})

	afterAll(() => {
		sqlite.close()
	})

	describe("GET /api/v4/ca", () => {
		it("should return the CA public key", async () => {
			const response = await request(ca, "GET", "/api/v4/ca")

			expect(response.status).toBe(200)
			expect(await response.text()).toBe(`${ed25519Key.ca().publicKey.split(" ").slice(0, 2).join(" ")} CN=SSH CA,O=Internet Widgets Pty Ltd,C=US\n`)
		})
	})

	describe("POST /api/v4/user/certificates", () => {
		it("should issue a certificate with a proof made for the request", async () => {
			const certificate = await parseCertificate(await issueUserCertificate(userKey))

			expect(certificate.listed.publicKey).toBe(fingerprint(userKey.publicKey))
			expect(certificate.listed.signingCa).toBe(fingerprint(ed25519Key.ca().publicKey))
		})

		it("should accept the proof header in any case", async () => {
			const response = await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"authorization": await getAccessToken(claims),
					"proof-of-possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
				},
				body: JSON.stringify({ public_key: publicKey(userKey), identity: await getIdentityToken(claims) }),
			}))

			expect(response.status).toBe(200)
		})

		it("should reject a request without a proof", async () => {
			const response = await request(ca, "POST", "/api/v4/user/certificates", {
				body: { public_key: publicKey(userKey), identity: await getIdentityToken(claims) },
				authorization: await getAccessToken(claims),
			})

			expect(response.status).toBe(400)
		})

		it("should reject a proof in the body", async () => {
			const response = await request(ca, "POST", "/api/v4/user/certificates", {
				body: {
					public_key: publicKey(userKey),
					identity: await getIdentityToken(claims),
					proof: generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
				},
				authorization: await getAccessToken(claims),
			})

			expect(response.status).toBe(400)
		})

		it.each([
			["another path", "POST", "/api/v4/host/certificates"],
			["another method", "DELETE", "/api/v4/user/certificates"],
			["the v3 path", "POST", "/api/v3/user/certificate"],
			["a path without the base path", "POST", "/user/certificates"],
		])("should reject a proof made for %s", async (_, method, path) => {
			const response = await issueUserCertificate(userKey, generateRequestProof(userKey, method, path))

			expect(response.status).toBe(400)
			expect(await errorMessages(response)).toContain("proof of possession signature validation failed")
		})

		it("should reject a v3 proof", async () => {
			const response = await issueUserCertificate(userKey, generateProof(userKey))

			expect(response.status).toBe(400)
			expect(await errorMessages(response)).toContain("proof of possession signature validation failed")
		})

		it("should reject a proof made for the request with the v3 namespace", async () => {
			const proof = generateRequestProof(userKey, "POST", "/api/v4/user/certificates", { namespace: "proof-of-possession@com.github.serverless-ssh-ca.andrewheberle" })
			const response = await issueUserCertificate(userKey, proof)

			expect(response.status).toBe(400)
		})

		it("should reject a proof made with another key", async () => {
			const response = await issueUserCertificate(userKey, generateRequestProof(otherKey, "POST", "/api/v4/user/certificates"))

			expect(response.status).toBe(400)
			expect(await errorMessages(response)).toContain("proof of possession fingerprint did not match public key")
		})

		it("should reject an expired proof", async () => {
			const proof = generateRequestProof(userKey, "POST", "/api/v4/user/certificates", { timestamp: Date.now() - 5 * 60 * 1000 })
			const response = await issueUserCertificate(userKey, proof)

			expect(response.status).toBe(400)
		})
	})

	describe("DELETE /api/v4/user/certificates/{serial}", () => {
		it("should revoke a certificate and include it in the KRL", async () => {
			const issued = await parseCertificate(await issueUserCertificate(userKey))
			const serial = serialOf(issued)

			const response = await revokeCertificate("user", serial, revokeProof(userKey, "user", serial))
			expect(response.status).toBe(200)
			expect(await response.json()).toEqual({ revoked_at: expect.any(String) })

			// a second revocation conflicts with the first
			expect((await revokeCertificate("user", serial, revokeProof(userKey, "user", serial))).status).toBe(409)

			// ssh-keygen treats the certificate as revoked by the KRL
			expect(isRevoked(await getKrl(ca, "user"), issued.text)).toBe(true)
		})

		it("should not accept the proof from a certificate request", async () => {
			const proof = generateRequestProof(userKey, "POST", "/api/v4/user/certificates")
			const serial = serialOf(await parseCertificate(await issueUserCertificate(userKey, proof)))

			// replaying the proof sent with the request cannot revoke the certificate
			const response = await revokeCertificate("user", serial, proof)
			expect(response.status).toBe(400)
			expect(await errorMessages(response)).toContain("proof of possession signature validation failed")
		})

		it("should not accept a proof made for another certificate", async () => {
			const first = serialOf(await parseCertificate(await issueUserCertificate(userKey)))
			const second = serialOf(await parseCertificate(await issueUserCertificate(userKey)))

			const response = await revokeCertificate("user", second, revokeProof(userKey, "user", first))
			expect(response.status).toBe(400)

			// the certificate is still revokable
			expect((await revokeCertificate("user", second, revokeProof(userKey, "user", second))).status).toBe(200)
		})

		it("should not accept a proof made for the host endpoint", async () => {
			const serial = serialOf(await parseCertificate(await issueUserCertificate(userKey)))

			const response = await revokeCertificate("user", serial, revokeProof(userKey, "host", serial))
			expect(response.status).toBe(400)
		})

		it("should report a certificate issued for another key as not found", async () => {
			const serial = serialOf(await parseCertificate(await issueUserCertificate(userKey)))

			const response = await revokeCertificate("user", serial, revokeProof(otherKey, "user", serial))
			expect(response.status).toBe(404)
		})

		it("should report an unknown certificate as not found", async () => {
			const response = await revokeCertificate("user", 1234n, revokeProof(userKey, "user", 1234n))
			expect(response.status).toBe(404)
		})

		it("should reject a request without a proof", async () => {
			const serial = serialOf(await parseCertificate(await issueUserCertificate(userKey)))

			const response = await request(ca, "DELETE", `/api/v4/user/certificates/${serial}`)
			expect(response.status).toBe(400)
		})

		it.each([
			["a leading zero", "01234"],
			["a negative value", "-1"],
			["a hex value", "0x10"],
			["a non-numeric value", "abc"],
			["a value larger than 64 bits", "18446744073709551616"],
		])("should reject a serial with %s", async (_, serial) => {
			const response = await revokeCertificate("user", serial, revokeProof(userKey, "user", serial))
			expect(response.status).toBe(400)
		})
	})

	describe("host certificates", () => {
		it("should issue, renew and revoke a host certificate", async () => {
			const issued = await parseCertificate(await issueHostCertificate(hostKey, ["renew_host"]))
			const serial = serialOf(issued)

			const renewal = await request(ca, "POST", `/api/v4/host/certificates/${serial}/renew`, {
				body: { certificate: Buffer.from(issued.text).toString("base64") },
				proof: generateRequestProof(hostKey, "POST", `/api/v4/host/certificates/${serial}/renew`),
			})
			const renewed = await parseCertificate(renewal)
			expect(serialOf(renewed)).not.toBe(serial)
			expect(renewed.listed.kind).toBe("host")
			expect(renewed.listed.principals).toEqual(issued.listed.principals)
			expect(renewed.listed.publicKey).toBe(fingerprint(hostKey.publicKey))

			// a host certificate cannot be revoked through the user endpoint
			expect((await revokeCertificate("user", serial, revokeProof(hostKey, "user", serial))).status).toBe(404)

			const response = await revokeCertificate("host", serial, revokeProof(hostKey, "host", serial))
			expect(response.status).toBe(200)

			// ssh-keygen treats the revoked certificate as revoked by the KRL,
			// but not the renewed one
			const krl = await getKrl(ca, "host")
			expect(isRevoked(krl, issued.text)).toBe(true)
			expect(isRevoked(krl, renewed.text)).toBe(false)

			// a revoked certificate cannot be renewed
			const revokedRenewal = await request(ca, "POST", `/api/v4/host/certificates/${serial}/renew`, {
				body: { certificate: Buffer.from(issued.text).toString("base64") },
				proof: generateRequestProof(hostKey, "POST", `/api/v4/host/certificates/${serial}/renew`),
			})
			expect(revokedRenewal.status).toBe(400)
		})

		it("should not renew a certificate with a proof made for another request", async () => {
			const issued = await parseCertificate(await issueHostCertificate(hostKey, ["proof_host"]))
			const serial = serialOf(issued)
			const body = { certificate: Buffer.from(issued.text).toString("base64") }

			for (const proof of [
				generateRequestProof(hostKey, "DELETE", `/api/v4/host/certificates/${serial}`),
				generateRequestProof(hostKey, "POST", "/api/v4/host/certificates"),
				generateRequestProof(hostKey, "POST", `/api/v4/host/certificates/${serial + 1n}/renew`),
				generateProof(hostKey),
			]) {
				const response = await request(ca, "POST", `/api/v4/host/certificates/${serial}/renew`, { body, proof })
				expect(response.status).toBe(400)
			}
		})

		it("should not renew a certificate with a proof made with another key", async () => {
			const issued = await parseCertificate(await issueHostCertificate(hostKey, ["other_key_host"]))
			const serial = serialOf(issued)

			const response = await request(ca, "POST", `/api/v4/host/certificates/${serial}/renew`, {
				body: { certificate: Buffer.from(issued.text).toString("base64") },
				proof: generateRequestProof(otherKey, "POST", `/api/v4/host/certificates/${serial}/renew`),
			})
			expect(response.status).toBe(400)
			expect(await errorMessages(response)).toContain("proof of possession fingerprint did not match public key")
		})

		it("should not renew a certificate whose serial is not the one in the path", async () => {
			const first = await parseCertificate(await issueHostCertificate(hostKey, ["first_host"]))
			const second = await parseCertificate(await issueHostCertificate(hostKey, ["second_host"]))
			const serial = serialOf(second)

			const response = await request(ca, "POST", `/api/v4/host/certificates/${serial}/renew`, {
				body: { certificate: Buffer.from(first.text).toString("base64") },
				proof: generateRequestProof(hostKey, "POST", `/api/v4/host/certificates/${serial}/renew`),
			})
			expect(response.status).toBe(400)
			expect(await errorMessages(response)).toContain("certificate serial did not match the serial in the path")
		})

		it("should not issue a host certificate with a proof made for the user endpoint", async () => {
			const response = await request(ca, "POST", "/api/v4/host/certificates", {
				body: {
					public_key: publicKey(hostKey),
					identity: await getIdentityToken(claims),
					principals: ["user_proof_host"],
				},
				proof: generateRequestProof(hostKey, "POST", "/api/v4/user/certificates"),
				authorization: await getAccessToken(claims),
			})
			expect(response.status).toBe(400)
		})
	})
})
