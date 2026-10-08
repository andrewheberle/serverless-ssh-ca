import { describe, it, expect } from "vitest"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { bindingsFromEnv, InvalidConfigurationError, secretFromFile, secretFromString } from "../src/node/index.js"
import type { CaDatabase } from "../src/types.js"

const DB: CaDatabase = {
	prepare: () => { throw new Error("not used") },
	batch: async () => [],
	exec: async () => undefined,
}
const PRIVATE_KEY = secretFromString("key")

// the vars from the example wrangler.jsonc
const valid: Record<string, string> = {
	ISSUER_DN: "CN=SSH CA,O=Internet Widgets Pty Ltd,C=US",
	JWT_JWKS_URL: "https://idp.example.com/.well-known/jwks.json",
	JWT_AUD: "audience",
	JWT_ISSUER: "https://idp.example.com",
	JWT_ALGORITHMS: "RS256",
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: "groups",
	SSH_CERTIFICATE_LIFETIME: "24 hours",
	SSH_CERTIFICATE_PRINCIPALS: "ssh-admin",
	SSH_CERTIFICATE_INCLUDE_SELF: "false",
	SSH_CERTIFICATE_INCLUDE_SELF_EMAIL: "false",
	SSH_CERTIFICATE_EXTENSIONS: "permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc",
	SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: "",
	SSH_HOST_CERTIFICATE_ALLOWED_ROLES: "",
	SSH_HOST_CERTIFICATE_LIFETIME: "30 days",
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: "90 seconds",
	DB_CERTIFICATE_RETENTION: "1 year",
	LOG_LEVEL: "info",
}

const without = (key: string): Record<string, string> => Object.fromEntries(Object.entries(valid).filter(([k]) => k !== key))

const errorFor = (source: Record<string, string | undefined>): string => {
	try {
		bindingsFromEnv({ DB, PRIVATE_KEY }, source)
	} catch (err) {
		expect(err).toBeInstanceOf(InvalidConfigurationError)
		return err instanceof Error ? err.message : ""
	}
	throw new Error("expected an InvalidConfigurationError")
}

describe("bindingsFromEnv", () => {
	it("should return the bindings for a valid environment", () => {
		const env = bindingsFromEnv({ DB, PRIVATE_KEY }, { ...valid, UNRELATED: "ignored" })

		expect(env).toEqual({ ...valid, DB, PRIVATE_KEY })
		expect(env).not.toHaveProperty("UNRELATED")
	})

	it("should read process.env by default", () => {
		const saved = { ...process.env }
		try {
			Object.assign(process.env, valid)

			expect(bindingsFromEnv({ DB, PRIVATE_KEY }).ISSUER_DN).toBe(valid.ISSUER_DN)
		} finally {
			for (const key of Object.keys(valid)) {
				if (saved[key] === undefined) {
					delete process.env[key]
				} else {
					process.env[key] = saved[key]
				}
			}
		}
	})

	it("should allow optional variables to be unset", () => {
		const optional = [
			"JWT_AUD", "SSH_CERTIFICATE_PRINCIPALS", "SSH_CERTIFICATE_INCLUDE_SELF", "SSH_CERTIFICATE_INCLUDE_SELF_EMAIL",
			"SSH_HOST_CERTIFICATE_ALLOWED_EMAILS", "SSH_HOST_CERTIFICATE_ALLOWED_ROLES", "LOG_LEVEL",
		]
		const source = Object.fromEntries(Object.entries(valid).filter(([k]) => !optional.includes(k)))

		expect(() => bindingsFromEnv({ DB, PRIVATE_KEY }, source)).not.toThrow()
	})

	it("should allow no certificate extensions", () => {
		expect(bindingsFromEnv({ DB, PRIVATE_KEY }, { ...valid, SSH_CERTIFICATE_EXTENSIONS: "" }).SSH_CERTIFICATE_EXTENSIONS).toBe("")
	})

	it("should allow infinite retention", () => {
		expect(bindingsFromEnv({ DB, PRIVATE_KEY }, { ...valid, DB_CERTIFICATE_RETENTION: "infinite" }).DB_CERTIFICATE_RETENTION).toBe("infinite")
	})

	it.each([
		"ISSUER_DN",
		"JWT_JWKS_URL",
		"JWT_ISSUER",
		"JWT_ALGORITHMS",
		"JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM",
		"SSH_CERTIFICATE_EXTENSIONS",
		"SSH_CERTIFICATE_LIFETIME",
		"SSH_HOST_CERTIFICATE_LIFETIME",
		"CERTIFICATE_REQUEST_TIME_SKEW_MAX",
		"DB_CERTIFICATE_RETENTION",
	])("should report a missing %s", (key) => {
		expect(errorFor(without(key))).toContain(key)
	})

	it.each([
		["ISSUER_DN", " "],
		["JWT_JWKS_URL", "not a url"],
		["JWT_JWKS_URL", "file:///etc/jwks.json"],
		["SSH_CERTIFICATE_LIFETIME", "forever"],
		["SSH_CERTIFICATE_LIFETIME", "0 seconds"],
		["SSH_HOST_CERTIFICATE_LIFETIME", "-1 day"],
		["CERTIFICATE_REQUEST_TIME_SKEW_MAX", "soon"],
		["DB_CERTIFICATE_RETENTION", "1 fortnight"],
		["SSH_CERTIFICATE_INCLUDE_SELF", "yes"],
		["SSH_CERTIFICATE_INCLUDE_SELF_EMAIL", "TRUE"],
		["LOG_LEVEL", "verbose"],
	])("should report an invalid %s of %j", (key, value) => {
		expect(errorFor({ ...valid, [key]: value })).toContain(key)
	})

	it("should report every invalid variable at once", () => {
		const message = errorFor({ ...without("ISSUER_DN"), LOG_LEVEL: "verbose" })

		expect(message).toContain("ISSUER_DN")
		expect(message).toContain("LOG_LEVEL")
	})
})

describe("secrets", () => {
	it("secretFromString should return the string", async () => {
		expect(await secretFromString("private key").get()).toBe("private key")
	})

	it("secretFromFile should read the file each time", async () => {
		const dir = mkdtempSync(join(tmpdir(), "ssh-ca-secret-"))
		const path = join(dir, "ca_key")

		try {
			const secret = secretFromFile(path)

			writeFileSync(path, "first")
			expect(await secret.get()).toBe("first")

			writeFileSync(path, "second")
			expect(await secret.get()).toBe("second")
		} finally {
			rmSync(dir, { recursive: true, force: true })
		}
	})

	it("secretFromFile should reject if the file cannot be read", async () => {
		await expect(secretFromFile(join(tmpdir(), "ssh-ca-missing", "ca_key")).get()).rejects.toThrow()
	})
})
