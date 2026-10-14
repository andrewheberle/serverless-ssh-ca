import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { SshCertificate } from "../src/ssh/certificate.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { getAccessToken, getIdentityToken } from "./helpers/token.js"
import { generateProof, generateRequestProof } from "./helpers/proof.js"
import { generateKey, signCertificate } from "./helpers/ssh-keygen.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as rsaKey } from "./keys/rsa.js"
import type { TestKey } from "./keys/types.js"

// The responses to requests the CA refuses to issue or renew a certificate for
// are relied on by the client and its end-to-end tests, so their status and
// body are pinned here for every endpoint that issues or renews a certificate.

const email = "user@example.com"
const sub = "user123"
const caKey = ed25519Key.ca()
const userKey = ecdsaKey.user()
const hostKey = ecdsaKey.host()
const base64 = (value: string): string => Buffer.from(value).toString("base64")

const newCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(caKey.privateKey),
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: email,
	...overrides,
}))

const validationError = (message: string, path: string[]) => ({
	success: false,
	result: {},
	errors: [{ code: 7001, message, path }],
})

const unprocessable = (message: string) => ({
	success: false,
	result: {},
	errors: [{ code: 7007, message }],
})

const internalError = {
	success: false,
	result: {},
	errors: [{ code: 7009, message: "Internal Error" }],
}

type IssueEndpoint = {
	name: string
	user: boolean
	request: (ca: SshCa, body?: Record<string, unknown>) => Promise<Response>
}

const issueEndpoints: IssueEndpoint[] = [
	{
		name: "POST /api/v3/user/certificate",
		user: true,
		request: async (ca, body = {}) => await ca.fetch(new Request("http://example.com/api/v3/user/certificate", {
			method: "POST",
			headers: { "Content-Type": "application/json", "Authorization": await getAccessToken({ sub, email }) },
			body: JSON.stringify({ public_key: base64(userKey.publicKey), proof: generateProof(userKey), identity: await getIdentityToken({ sub, email }), ...body }),
		})),
	},
	{
		name: "POST /api/v3/host/certificate",
		user: false,
		request: async (ca, body = {}) => await ca.fetch(new Request("http://example.com/api/v3/host/certificate", {
			method: "POST",
			headers: { "Content-Type": "application/json", "Authorization": await getAccessToken({ sub, email }) },
			body: JSON.stringify({ public_key: base64(hostKey.publicKey), proof: generateProof(hostKey), identity: await getIdentityToken({ sub, email }), principals: ["test_host"], ...body }),
		})),
	},
	{
		name: "POST /api/v4/user/certificates",
		user: true,
		request: async (ca, body = {}) => await ca.fetch(new Request("http://example.com/api/v4/user/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": await getAccessToken({ sub, email }),
				"Proof-Of-Possession": generateRequestProof(userKey, "POST", "/api/v4/user/certificates"),
			},
			body: JSON.stringify({ public_key: base64(userKey.publicKey), identity: await getIdentityToken({ sub, email }), ...body }),
		})),
	},
	{
		name: "POST /api/v4/host/certificates",
		user: false,
		request: async (ca, body = {}) => await ca.fetch(new Request("http://example.com/api/v4/host/certificates", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Authorization": await getAccessToken({ sub, email }),
				"Proof-Of-Possession": generateRequestProof(hostKey, "POST", "/api/v4/host/certificates"),
			},
			body: JSON.stringify({ public_key: base64(hostKey.publicKey), identity: await getIdentityToken({ sub, email }), principals: ["test_host"], ...body }),
		})),
	},
]

describe.each(issueEndpoints)("responses to certificates the CA will not issue ($name)", ({ request, user }) => {
	it("should issue a certificate", async () => {
		const response = await request(newCa())
		expect(response.status).toBe(200)
	})

	it.runIf(user)("should return 422 for an extension that is not allowed", async () => {
		const response = await request(newCa(), { extensions: ["permit-everything"] })
		expect(response.status).toBe(422)
		expect(await response.json()).toEqual(unprocessable("permit-everything is not allowed"))
	})

	it.runIf(user)("should return 422 for a certificate without principals", async () => {
		const response = await request(newCa({ SSH_CERTIFICATE_PRINCIPALS: "" }))
		expect(response.status).toBe(422)
		expect(await response.json()).toEqual(unprocessable("a certificate must have at least one principal"))
	})

	it("should return 500 for a CA key of a type that is not supported", async () => {
		const response = await request(newCa({ PRIVATE_KEY: secretFromString(rsaKey.ca().privateKey) }))
		expect(response.status).toBe(500)
		expect(await response.json()).toEqual(internalError)
	})

	it("should return 500 for a CA key that cannot be parsed", async () => {
		const response = await request(newCa({ PRIVATE_KEY: secretFromString("not a key") }))
		expect(response.status).toBe(500)
		expect(await response.json()).toEqual(internalError)
	})
})

type RenewEndpoint = {
	name: string
	v3: boolean
	request: (ca: SshCa, certificate: string, key: TestKey, options?: { proofKey?: TestKey, lifetime?: number }) => Promise<Response>
}

const renewEndpoints: RenewEndpoint[] = [
	{
		name: "POST /api/v3/host/renew",
		v3: true,
		request: async (ca, certificate, key, options = {}) => await ca.fetch(new Request("http://example.com/api/v3/host/renew", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				certificate: base64(certificate),
				public_key: base64(key.publicKey),
				proof: generateProof(options.proofKey ?? key),
				...(options.lifetime === undefined ? {} : { lifetime: options.lifetime }),
			}),
		})),
	},
	{
		name: "POST /api/v4/host/certificates/{serial}/renew",
		v3: false,
		request: async (ca, certificate, key, options = {}) => {
			const path = `/api/v4/host/certificates/${SshCertificate.parse(certificate).serial}/renew`
			return await ca.fetch(new Request(`http://example.com${path}`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"Proof-Of-Possession": generateRequestProof(options.proofKey ?? key, "POST", path),
				},
				body: JSON.stringify({
					certificate: base64(certificate),
					...(options.lifetime === undefined ? {} : { lifetime: options.lifetime }),
				}),
			}))
		},
	},
]

const hostCertificate = (options: { key?: TestKey, ca?: TestKey, kind?: "user" | "host", principals?: string[], validity?: string, serial?: bigint } = {}): string =>
	signCertificate(options.ca ?? caKey, (options.key ?? hostKey).publicKey, {
		kind: options.kind ?? "host",
		keyId: "host_test_host",
		principals: options.principals ?? ["test_host"],
		validity: options.validity ?? "-1m:+2d",
		...(options.serial === undefined ? {} : { serial: options.serial }),
	})

describe.each(renewEndpoints)("responses to certificates the CA will not renew ($name)", ({ request, v3 }) => {
	const notRenewable = (message: string) => validationError(message, ["body"])

	it("should renew a certificate for no longer than the certificate it renews", async () => {
		const certificate = hostCertificate({ validity: "-1m:+2d" })
		const response = await request(newCa(), certificate, hostKey)
		expect(response.status).toBe(200)

		const renewed = SshCertificate.parse(Buffer.from((await response.json() as { certificate: string }).certificate, "base64").toString())
		const original = SshCertificate.parse(certificate)
		expect(renewed.validBefore.getTime() - renewed.validAfter.getTime()).toBe(original.validBefore.getTime() - original.validAfter.getTime())
		expect(renewed.principals).toEqual(["test_host"])
	})

	it("should renew a certificate for the lifetime requested when it is shorter", async () => {
		const response = await request(newCa(), hostCertificate({ validity: "-1m:+20d" }), hostKey, { lifetime: 86400 })
		expect(response.status).toBe(200)

		const renewed = SshCertificate.parse(Buffer.from((await response.json() as { certificate: string }).certificate, "base64").toString())
		expect(renewed.validBefore.getTime() - renewed.validAfter.getTime()).toBe(86400 * 1000)
	})

	it("should return 400 for a certificate that has been renewed already", async () => {
		const ca = newCa()
		const certificate = hostCertificate()
		expect((await request(ca, certificate, hostKey)).status).toBe(200)

		const response = await request(ca, certificate, hostKey)
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(notRenewable("the provided certificate is revoked"))
	})

	// the serial of these certificates was never issued by the CA, as in the
	// client's end-to-end tests, so the certificate is checked before the
	// database is
	it.each([
		["is expired", { validity: "-2h:-1h", serial: 1n }, "the provided certificate is expired"],
		["is not yet valid", { validity: "+1h:+2h", serial: 1n }, "the provided certificate is not yet valid"],
		["was not signed by this CA", { ca: ed25519Key.user(), serial: 1n }, "the provided certificate was not signed by this CA"],
		["is a user certificate", { kind: "user" as const }, "the provided certificate is not a host certificate"],
		["has a wildcard principal", { principals: ["*.example.com"] }, "the provided certificate cannot be renewed: host certificate principal \"*.example.com\" must not contain wildcard or pattern characters (*, ?, ! or ,)"],
	])("should return 400 for a certificate that %s", async (_case, options, message) => {
		const response = await request(newCa(), hostCertificate(options), hostKey)
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(notRenewable(message))
	})

	it("should return 400 for a certificate for an RSA key that is too small", async () => {
		const key = generateKey("rsa", 1024)
		const response = await request(newCa(), hostCertificate({ key }), key)
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(notRenewable("the provided certificate cannot be renewed: RSA keys must be at least 2048 bits, not 1024"))
	})

	it("should return 400 for a proof made with another key", async () => {
		const response = await request(newCa(), hostCertificate(), hostKey, { proofKey: ecdsaKey.user() })
		expect(response.status).toBe(400)
		expect(await response.json()).toEqual(v3
			? validationError("proof of possession fingerprints did not match public_key and/or certificate", ["body"])
			: validationError("proof of possession fingerprint did not match public key", ["headers", "Proof-Of-Possession"]))
	})

	it("should return 500 for a CA key of a type that is not supported", async () => {
		const response = await request(newCa({ PRIVATE_KEY: secretFromString(rsaKey.ca().privateKey) }), hostCertificate(), hostKey)
		expect(response.status).toBe(500)
		expect(await response.json()).toEqual(internalError)
	})

	it("should return 500 for a CA key that cannot be parsed", async () => {
		const response = await request(newCa({ PRIVATE_KEY: secretFromString("not a key") }), hostCertificate(), hostKey)
		expect(response.status).toBe(500)
		expect(await response.json()).toEqual(internalError)
	})
})
