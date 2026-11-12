import { describe, it, expect } from "vitest"
import { createSshCa, InvalidConfigurationError } from "../src/index.js"
import { caConfig } from "../src/config.js"
import { createApp } from "../src/router.js"
import { bindingsFromEnv, secretFromString } from "../src/node/index.js"
import type { CaDatabase, SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"

const DB: CaDatabase = { prepare: () => { throw new Error("not used") }, batch: async () => [], exec: async () => undefined }
const PRIVATE_KEY = secretFromString("key")

// the vars of a valid configuration, as environment variables
const source: Record<string, string> = {
	ISSUER_DN: "CN=SSH CA",
	JWT_JWKS_URL: "https://idp.example.com/.well-known/jwks.json",
	JWT_AUD: "audience",
	JWT_ISSUER: "https://idp.example.com",
	JWT_ALGORITHMS: "RS256",
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: "groups",
	SSH_CERTIFICATE_LIFETIME: "24 hours",
	SSH_CERTIFICATE_EXTENSIONS: "permit-pty",
	SSH_HOST_CERTIFICATE_LIFETIME: "30 days",
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: "90 seconds",
	DB_CERTIFICATE_RETENTION: "1 year",
}

// whether a configuration is accepted, or the error it is refused with
const outcome = (run: () => unknown): "accepted" | string => {
	try {
		run()
		return "accepted"
	} catch (err) {
		expect(err).toBeInstanceOf(InvalidConfigurationError)
		return err instanceof Error ? err.message : String(err)
	}
}

// a configuration as accepted or refused by createSshCa and bindingsFromEnv,
// which must agree
const bothRuntimes = (vars: Record<string, string | undefined>): "accepted" | string => {
	const env = { ...source, ...vars }
	const fromEnv = outcome(() => bindingsFromEnv({ DB, PRIVATE_KEY }, env))
	const created = outcome(() => createSshCa({ ...env, DB, PRIVATE_KEY } as unknown as SshCaBindings))
	expect(fromEnv).toBe(created)
	return created
}

describe("URLs that authenticate requesters (#575)", () => {
	it.each(["JWT_JWKS_URL", "OIDC_USERINFO_URL"])("should refuse an http %s for another host", (name) => {
		expect(bothRuntimes({ [name]: "http://idp.example.com/path" })).toContain(name)
	})

	it.each([
		"http://localhost:8080/path",
		"http://127.0.0.1:8080/path",
		"http://127.1.2.3/path",
		"http://[::1]:8080/path",
		"https://idp.example.com/path",
	])("should accept %s", (url) => {
		expect(bothRuntimes({ JWT_JWKS_URL: url, OIDC_USERINFO_URL: url })).toBe("accepted")
	})

	it.each(["http://localhost.example.com/path", "http://128.0.0.1/path", "ftp://localhost/path", "not a url"])("should refuse %s", (url) => {
		expect(bothRuntimes({ JWT_JWKS_URL: url })).toContain("JWT_JWKS_URL")
	})

	it("should treat an empty OIDC_USERINFO_URL as not set", () => {
		expect(bothRuntimes({ OIDC_USERINFO_URL: "" })).toBe("accepted")
		expect(caConfig(makeEnv({ OIDC_USERINFO_URL: "" })).userinfoUrl).toBeUndefined()
	})
})

describe("the same rules on every runtime (#576)", () => {
	it.each([
		["unset", undefined],
		["empty", ""],
		["blank", " "],
		["a list of empty entries", " , "],
	])("should refuse JWT_AUD when it is %s", (_name, aud) => {
		expect(bothRuntimes({ JWT_AUD: aud })).toContain("JWT_AUD")
	})

	it("should allow SSH_CERTIFICATE_EXTENSIONS to be unset, meaning no extensions", () => {
		expect(bothRuntimes({ SSH_CERTIFICATE_EXTENSIONS: undefined })).toBe("accepted")
		expect(caConfig(makeEnv({ SSH_CERTIFICATE_EXTENSIONS: undefined })).extensions).toEqual([])
	})

	it("should return the variables unchanged from bindingsFromEnv, and only those the CA reads", () => {
		const env = bindingsFromEnv({ DB, PRIVATE_KEY }, { ...source, JWT_ALGORITHMS: "RS256, ES256", PATH: "/usr/bin" })

		expect(env.JWT_ALGORITHMS).toBe("RS256, ES256")
		expect(env).not.toHaveProperty("PATH")
		expect(env.DB).toBe(DB)
		expect(env.PRIVATE_KEY).toBe(PRIVATE_KEY)
	})
})

describe("list settings (#577)", () => {
	it("should trim each entry", () => {
		const config = caConfig(makeEnv({
			JWT_ALGORITHMS: "RS256, ES256",
			JWT_AUD: "a, b",
			SSH_CERTIFICATE_EXTENSIONS: "permit-pty, permit-user-rc",
			SSH_HOST_CERTIFICATE_ALLOWED_ROLES: ["ops ", " admins"],
		}))

		expect(config.algorithms).toEqual(["RS256", "ES256"])
		expect(config.audience).toEqual(["a", "b"])
		expect(config.extensions).toEqual(["permit-pty", "permit-user-rc"])
		expect(config.hostAllowedRoles).toEqual(["ops", "admins"])
	})

	it.each([
		["JWT_ALGORITHMS", "RS256,"],
		["JWT_AUD", "a,,b"],
		["JWT_ACCESS_TOKEN_AUD", "a,"],
		["SSH_CERTIFICATE_EXTENSIONS", "permit-pty,,permit-user-rc"],
		["SSH_CERTIFICATE_PRINCIPALS", "ssh-admin,"],
		["SSH_HOST_CERTIFICATE_ALLOWED_EMAILS", "admin@example.com,"],
		["SSH_HOST_CERTIFICATE_ALLOWED_ROLES", "ops,"],
	])("should refuse %s of %j with an empty entry", (name, value) => {
		expect(bothRuntimes({ [name]: value })).toContain(name)
	})

	it.each([
		"JWT_ACCESS_TOKEN_AUD",
		"SSH_CERTIFICATE_EXTENSIONS",
		"SSH_CERTIFICATE_PRINCIPALS",
		"SSH_HOST_CERTIFICATE_ALLOWED_EMAILS",
		"SSH_HOST_CERTIFICATE_ALLOWED_ROLES",
	])("should treat an empty %s as an empty list", (name) => {
		expect(bothRuntimes({ [name]: "" })).toBe("accepted")
	})

	it.each(["HS256", "none", "bogus", "RS256,HS256"])("should refuse JWT_ALGORITHMS of %j", (algorithms) => {
		expect(bothRuntimes({ JWT_ALGORITHMS: algorithms })).toContain("JWT_ALGORITHMS")
	})

	it.each(["RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512,EdDSA,Ed25519"])("should accept JWT_ALGORITHMS of %j", (algorithms) => {
		expect(bothRuntimes({ JWT_ALGORITHMS: algorithms })).toBe("accepted")
	})

	it("should lowercase the email addresses allowed host certificates", () => {
		expect(caConfig(makeEnv({ SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: "Admin@Example.com" })).hostAllowedEmails).toEqual(["admin@example.com"])
	})

	it.each([["permit pty"], ["permit-pty,x"]])("should refuse an extension of %j", (extension) => {
		expect(() => caConfig(makeEnv({ SSH_CERTIFICATE_EXTENSIONS: [extension] }))).toThrow("SSH_CERTIFICATE_EXTENSIONS")
	})

	it("should accept a custom extension", () => {
		expect(bothRuntimes({ SSH_CERTIFICATE_EXTENSIONS: "permit-pty,login@example.com" })).toBe("accepted")
	})
})

describe("durations (#578)", () => {
	it.each([
		["SSH_CERTIFICATE_LIFETIME", "4 minutes"],
		["SSH_CERTIFICATE_LIFETIME", "1.0001 hours"],
		["SSH_HOST_CERTIFICATE_LIFETIME", "23 hours"],
		["SSH_HOST_CERTIFICATE_LIFETIME", "1.00001 days"],
		["CERTIFICATE_REQUEST_TIME_SKEW_MAX", "0 seconds"],
		["CERTIFICATE_REQUEST_TIME_SKEW_MAX", "301 seconds"],
		["CERTIFICATE_REQUEST_TIME_SKEW_MAX", "1 hour"],
	])("should refuse %s of %j", (name, value) => {
		expect(bothRuntimes({ [name]: value })).toContain(name)
	})

	it.each([
		["SSH_CERTIFICATE_LIFETIME", "5 minutes", 300],
		["SSH_CERTIFICATE_LIFETIME", "5.5 minutes", 330],
		["SSH_CERTIFICATE_LIFETIME", "0.7 hours", 2520],
		["SSH_HOST_CERTIFICATE_LIFETIME", "24 hours", 86400],
		["SSH_HOST_CERTIFICATE_LIFETIME", "1.5 days", 129600],
	])("should accept %s of %j as %d seconds", (name, value, expected) => {
		expect(bothRuntimes({ [name]: value })).toBe("accepted")
		const config = caConfig(makeEnv({ [name]: value }))
		expect(name === "SSH_CERTIFICATE_LIFETIME" ? config.certificateLifetime : config.hostCertificateLifetime).toBe(expected)
	})

	it("should accept a skew of up to 5 minutes", () => {
		expect(bothRuntimes({ CERTIFICATE_REQUEST_TIME_SKEW_MAX: "5 minutes" })).toBe("accepted")
		expect(caConfig(makeEnv({ CERTIFICATE_REQUEST_TIME_SKEW_MAX: "5 minutes" })).requestTimeSkewMax).toBe(300000)
	})

	it.each([
		["/api/v4/user/certificates", "SSH_CERTIFICATE_LIFETIME", "5 minutes"],
		["/api/v4/host/certificates", "SSH_HOST_CERTIFICATE_LIFETIME", "24 hours"],
	])("should never publish a lifetime for %s whose minimum is above its maximum", (path, name, value) => {
		const schema = createApp(makeEnv({ [name]: value })).schema
		const body = schema.paths?.[path]?.post?.requestBody
		const lifetime = JSON.parse(JSON.stringify(body)).content["application/json"].schema
		const properties = lifetime.properties ?? (schema.components?.schemas?.[lifetime.$ref?.split("/").pop()] as { properties: Record<string, unknown> }).properties
		const { minimum, maximum } = properties.lifetime as { minimum: number, maximum: number }
		expect(minimum).toBeLessThanOrEqual(maximum)
	})
})
