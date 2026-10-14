import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { seconds } from "itty-time"
import { issueHostCertificate, issueUserCertificate, renewHostCertificate, type AuthorityConfig, type IssueResult, type RenewResult } from "../src/authority.js"
import { isRevoked, revokeCertificate } from "../src/db/index.js"
import { logger } from "../src/logger.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { Requester } from "../src/requester.js"
import type { SshCertificate } from "../src/ssh/certificate.js"
import type { SshCaBindings } from "../src/types.js"
import { split } from "../src/utils.js"
import { makeEnv } from "./env.js"
import { failingCertificateWrites, hostCertificate, unavailableDatabase } from "./helpers/certificate.js"
import { pub } from "./helpers/keys.js"
import { fingerprint, generateKey, listCertificate } from "./helpers/ssh-keygen.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as rsaKey } from "./keys/rsa.js"
import type { TestKey } from "./keys/types.js"

const l = logger(makeEnv())

const config = (overrides: Partial<SshCaBindings> = {}, ca: TestKey = ed25519Key.ca()): SshCaBindings => makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ca.privateKey),
	...overrides,
})

const requester: Requester = { email: "test@example.com", sub: "user123", principals: ["testuser", "group1", "group2"] }

// the certificate of a result, failing the test when none was issued
const certificateOf = (result: IssueResult | RenewResult): SshCertificate => {
	if (result.kind !== "issued") {
		expect.fail(`no certificate was issued: ${JSON.stringify(result)}`)
	}
	return result.certificate
}

const lifetimeOf = (certificate: SshCertificate): number => (certificate.validBefore.getTime() - certificate.validAfter.getTime()) / 1000

const cas: [string, TestKey][] = [
	["ECDSA CA", ecdsaKey.ca()],
	["Ed25519 CA", ed25519Key.ca()],
]

describe("issueUserCertificate", () => {
	describe.each(cas)("with an %s", (_, ca) => {
		it.each([
			["RSA", rsaKey.user()],
			["ECDSA", ecdsaKey.user()],
			["Ed25519", ed25519Key.user()],
		])("should issue a certificate for an %s key", async (_key, key) => {
			const env = config({}, ca)
			const certificate = certificateOf(await issueUserCertificate(env, requester, pub(key), {}, l))

			// ssh-keygen verifies the signature
			const listed = listCertificate(certificate.toString())
			expect(listed.kind).toBe("user")
			expect(listed.signingCa).toBe(fingerprint(ca.publicKey))
			expect(listed.publicKey).toBe(fingerprint(key.publicKey))
			expect(listed.keyId).toBe(requester.email)
			expect([...listed.principals].sort()).toEqual([...requester.principals, ...split(env.SSH_CERTIFICATE_PRINCIPALS)].sort())
			expect(listed.extensions).toEqual(split(env.SSH_CERTIFICATE_EXTENSIONS).sort())
			expect(lifetimeOf(certificate)).toBe(seconds(env.SSH_CERTIFICATE_LIFETIME))
		})
	})

	it.each([
		["the local part of the email address", { SSH_CERTIFICATE_INCLUDE_SELF: true }, ["test"]],
		["the local part of the email address when set as a string", { SSH_CERTIFICATE_INCLUDE_SELF: "true" }, ["test"]],
		["the email address", { SSH_CERTIFICATE_INCLUDE_SELF_EMAIL: true }, ["test@example.com"]],
		["the local part and the email address", { SSH_CERTIFICATE_INCLUDE_SELF: true, SSH_CERTIFICATE_INCLUDE_SELF_EMAIL: true }, ["test", "test@example.com"]],
	])("should add %s to the principals when configured", async (_case, overrides, added) => {
		const certificate = certificateOf(await issueUserCertificate(config({ ...overrides, SSH_CERTIFICATE_PRINCIPALS: undefined }), requester, pub(ed25519Key.user()), {}, l))
		expect([...certificate.principals].sort()).toEqual([...added, ...requester.principals].sort())
	})

	it("should issue a certificate with fewer extensions when asked", async () => {
		const certificate = certificateOf(await issueUserCertificate(config(), requester, pub(ed25519Key.user()), { extensions: ["permit-user-rc"] }, l))
		expect(certificate.extensions).toEqual(["permit-user-rc"])
	})

	it("should not issue a certificate with an extension that is not allowed", async () => {
		expect(await issueUserCertificate(config(), requester, pub(ed25519Key.user()), { extensions: ["no-touch-required"] }, l))
			.toEqual({ kind: "notAllowed", message: "no-touch-required is not allowed" })
	})

	it("should not issue a certificate without principals", async () => {
		expect(await issueUserCertificate(config({ SSH_CERTIFICATE_PRINCIPALS: "" }), { ...requester, principals: [] }, pub(ed25519Key.user()), {}, l))
			.toEqual({ kind: "notAllowed", message: "a certificate must have at least one principal" })
	})

	it("should be valid from the current second for the requested lifetime", async () => {
		const before = Date.now()
		const certificate = certificateOf(await issueUserCertificate(config(), requester, pub(ed25519Key.user()), { lifetime: 3600 }, l))

		expect(certificate.validAfter.getTime()).toBeLessThanOrEqual(Date.now())
		expect(certificate.validAfter.getTime()).toBeGreaterThan(before - 1000)
		expect(lifetimeOf(certificate)).toBe(3600)
	})

	it("should not be valid for longer than the configured lifetime", async () => {
		const env = config()
		const certificate = certificateOf(await issueUserCertificate(env, requester, pub(ed25519Key.user()), { lifetime: seconds(env.SSH_CERTIFICATE_LIFETIME) + 3600 }, l))
		expect(lifetimeOf(certificate)).toBe(seconds(env.SSH_CERTIFICATE_LIFETIME))
	})

	it("should record the certificate so it can be revoked", async () => {
		const env = config()
		const certificate = certificateOf(await issueUserCertificate(env, requester, pub(ed25519Key.user()), {}, l))
		expect(await revokeCertificate(env, certificate.serial)).toHaveLength(1)
	})
})

describe("issueHostCertificate", () => {
	describe.each(cas)("with an %s", (_, ca) => {
		it.each([
			["RSA", rsaKey.host()],
			["ECDSA", ecdsaKey.host()],
			["Ed25519", ed25519Key.host()],
		])("should issue a certificate for an %s key", async (_key, key) => {
			const env = config({}, ca)
			const certificate = certificateOf(await issueHostCertificate(env, pub(key), { principals: ["test_host"] }, l))

			// ssh-keygen verifies the signature
			const listed = listCertificate(certificate.toString())
			expect(listed.kind).toBe("host")
			expect(listed.signingCa).toBe(fingerprint(ca.publicKey))
			expect(listed.publicKey).toBe(fingerprint(key.publicKey))
			expect(listed.keyId).toBe("host_test_host")
			expect(listed.principals).toEqual(["test_host"])
			expect(listed.extensions).toEqual([])
			expect(lifetimeOf(certificate)).toBe(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
		})
	})

	it("should use the first principal as the key ID", async () => {
		const certificate = certificateOf(await issueHostCertificate(config(), pub(ed25519Key.host()), { principals: ["first.example.com", "second.example.com"] }, l))
		expect(certificate.keyId).toBe("host_first.example.com")
		expect(certificate.principals).toEqual(["first.example.com", "second.example.com"])
	})

	it("should not issue a certificate without principals", async () => {
		expect(await issueHostCertificate(config(), pub(ed25519Key.host()), { principals: [] }, l))
			.toEqual({ kind: "notAllowed", message: "a certificate must have at least one principal" })
	})

	it("should not be valid for longer than the configured lifetime", async () => {
		const env = config()
		const certificate = certificateOf(await issueHostCertificate(env, pub(ed25519Key.host()), { principals: ["test_host"], lifetime: seconds(env.SSH_HOST_CERTIFICATE_LIFETIME) + 3600 }, l))
		expect(lifetimeOf(certificate)).toBe(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
	})
})

describe.each([
	["issueUserCertificate", (env: AuthorityConfig) => issueUserCertificate(env, requester, pub(ed25519Key.user()), {}, l)],
	["issueHostCertificate", (env: AuthorityConfig) => issueHostCertificate(env, pub(ed25519Key.host()), { principals: ["test_host"] }, l)],
	["renewHostCertificate", (env: AuthorityConfig) => renewHostCertificate(env, hostCertificate(ed25519Key.ca(), ed25519Key.host()), {}, l)],
] as const)("%s", (_name, operation) => {
	it("should report a CA key of a type that is not supported", async () => {
		expect(await operation(config({ PRIVATE_KEY: secretFromString(rsaKey.ca().privateKey) })))
			.toEqual({ kind: "keyMisconfigured", message: "CA key type rsa is not supported, the CA key must be Ed25519 or ECDSA" })
	})

	it("should report a CA key that cannot be parsed", async () => {
		expect(await operation(config({ PRIVATE_KEY: secretFromString("not a key") })))
			.toEqual({ kind: "keyMisconfigured", message: "error parsing private key" })
	})

	it("should not issue a certificate that cannot be recorded", async () => {
		expect(await operation(config({ DB: failingCertificateWrites(fromNodeSqlite(new DatabaseSync(":memory:"))) })))
			.toEqual({ kind: "storeUnavailable", message: "there was a problem recording the issued certificate" })
	})
})

describe("renewHostCertificate", () => {
	const caKey = ed25519Key.ca()
	const hostKey = ecdsaKey.host()
	const renew = async (env: AuthorityConfig, certificate: SshCertificate, lifetime?: number): Promise<RenewResult> =>
		await renewHostCertificate(env, certificate, lifetime === undefined ? {} : { lifetime }, l)

	it("should renew a certificate for the same key and principals, and revoke it", async () => {
		const env = config()
		const previous = hostCertificate(caKey, hostKey, { principals: ["first.example.com", "second.example.com"] })
		const renewed = certificateOf(await renew(env, previous))

		const listed = listCertificate(renewed.toString())
		expect(listed.kind).toBe("host")
		expect(listed.signingCa).toBe(fingerprint(caKey.publicKey))
		expect(listed.publicKey).toBe(fingerprint(hostKey.publicKey))
		expect(listed.keyId).toBe("host_first.example.com")
		expect(listed.principals).toEqual(["first.example.com", "second.example.com"])
		expect(renewed.serial).not.toBe(previous.serial)

		expect(await isRevoked(env, previous.serial)).toBe(true)
		expect(await isRevoked(env, renewed.serial)).toBe(false)
	})

	it("should renew a certificate for no longer than the certificate it renews", async () => {
		const previous = hostCertificate(caKey, hostKey, { validity: "-1m:+2d" })
		expect(lifetimeOf(certificateOf(await renew(config(), previous)))).toBe(lifetimeOf(previous))
	})

	it("should renew a certificate for the lifetime asked for when it is shorter", async () => {
		expect(lifetimeOf(certificateOf(await renew(config(), hostCertificate(caKey, hostKey), 86400)))).toBe(86400)
	})

	it("should renew a certificate for no longer than the configured lifetime", async () => {
		const env = config({ SSH_HOST_CERTIFICATE_LIFETIME: "7 days" })
		expect(lifetimeOf(certificateOf(await renew(env, hostCertificate(caKey, hostKey, { validity: "-1m:+30d" }))))).toBe(seconds("7 days"))
	})

	it("should renew a certificate whose validity starts a second in the future", async () => {
		expect(await renew(config(), hostCertificate(caKey, hostKey, { validity: "+1s:+1h" }))).toMatchObject({ kind: "issued" })
	})

	it("should not renew a certificate twice", async () => {
		const env = config()
		const previous = hostCertificate(caKey, hostKey)
		expect(await renew(env, previous)).toMatchObject({ kind: "issued" })
		expect(await renew(env, previous)).toEqual({ kind: "notRenewable", message: "the provided certificate is revoked" })
	})

	it.each([
		["was not signed by this CA", () => hostCertificate(ed25519Key.user(), hostKey), "the provided certificate was not signed by this CA"],
		["is expired", () => hostCertificate(caKey, hostKey, { validity: "-2h:-1h" }), "the provided certificate is expired"],
		["is not yet valid", () => hostCertificate(caKey, hostKey, { validity: "+1h:+2h" }), "the provided certificate is not yet valid"],
		["has a wildcard principal", () => hostCertificate(caKey, hostKey, { principals: ["test_host", "*.example.com"] }), "the provided certificate cannot be renewed: host certificate principal \"*.example.com\" must not contain wildcard or pattern characters (*, ?, ! or ,)"],
		["is for an RSA key that is too small", () => hostCertificate(caKey, generateKey("rsa", 1024)), "the provided certificate cannot be renewed: RSA keys must be at least 2048 bits, not 1024"],
	])("should not renew a certificate that %s", async (_case, certificate, message) => {
		expect(await renew(config(), certificate())).toEqual({ kind: "notRenewable", message })
	})

	it("should not renew a user certificate", async () => {
		const env = config()
		const certificate = certificateOf(await issueUserCertificate(env, requester, pub(ed25519Key.user()), {}, l))
		expect(await renew(env, certificate)).toEqual({ kind: "notRenewable", message: "the provided certificate is not a host certificate" })
	})

	// the client's end-to-end tests present certificates whose serial the CA
	// never issued, which must be reported for what is wrong with them
	it.each([
		["was not signed by this CA", () => hostCertificate(ed25519Key.user(), hostKey, { serial: 1n }), "the provided certificate was not signed by this CA"],
		["is expired", () => hostCertificate(caKey, hostKey, { validity: "-2h:-1h", serial: 1n }), "the provided certificate is expired"],
	])("should check a certificate that %s before using the database", async (_case, certificate, message) => {
		expect(await renew(config({ DB: unavailableDatabase() }), certificate())).toEqual({ kind: "notRenewable", message })
	})

	it("should report the database being unavailable when checking whether a certificate is revoked", async () => {
		expect(await renew(config({ DB: unavailableDatabase() }), hostCertificate(caKey, hostKey)))
			.toEqual({ kind: "storeUnavailable", message: "there was a problem checking whether the certificate presented for renewal is revoked" })
	})
})
