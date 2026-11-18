import { afterEach, describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import ca, { createSshCa } from "../src/index.js"
import { cloudflareClientIp } from "../src/router.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"
import { key as ed25519Key } from "./keys/ed25519.js"

// A configuration that is valid but will not fully work is warned about once
// when the CA is created, and still served, as refusing it would break
// configurations that 1.x accepts (#583)

const valid = (overrides: Partial<SshCaBindings> = {}): SshCaBindings => makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
	LOG_LEVEL: "warning",
	...overrides,
})

// a binding of the wrong type, as a misconfigured runtime could pass one. The
// cast is the point of these tests, as the types rule such bindings out
const wrong = <T>(value: unknown): T => value as T

// the message of a log entry at the given level, or undefined
const messageAt = (level: string, entry: unknown): string | undefined =>
	typeof entry === "object" && entry !== null && Reflect.get(entry, "level") === level ? String(Reflect.get(entry, "message")) : undefined

// the admin settings of a working admin UI, without roles
const admin = {
	ADMIN_JWT_HEADER: "Cf-Access-Jwt-Assertion",
	ADMIN_JWKS_URL: "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
	ADMIN_JWT_ISSUER: "https://team.cloudflareaccess.com",
	ADMIN_JWT_AUD: "audience",
	ADMIN_ALLOWED_EMAILS: "admin@example.com",
}

// the warnings logged while running `run`
const warningsWhile = (run: () => void): string[] => {
	const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
	run()
	return log.mock.calls.flatMap(([entry]) => messageAt("warning", entry) ?? [])
}

afterEach(() => {
	vi.restoreAllMocks()
})

describe("warnings about a configuration that will not fully work", () => {
	it("should warn about nothing for a working configuration", () => {
		expect(warningsWhile(() => createSshCa(valid()))).toEqual([])
	})

	it.each([
		["a missing DB", { DB: wrong<SshCaBindings["DB"]>(undefined) }, "the DB binding is missing or is not a database"],
		["a DB that is not a database", { DB: wrong<SshCaBindings["DB"]>({}) }, "the DB binding is missing or is not a database"],
		["a missing PRIVATE_KEY", { PRIVATE_KEY: wrong<SshCaBindings["PRIVATE_KEY"]>(undefined) }, "the PRIVATE_KEY binding is missing or is not a secret"],
		["a RATE_LIMITER that is not a rate limiter", { RATE_LIMITER: wrong<SshCaBindings["RATE_LIMITER"]>("oops") }, "the RATE_LIMITER binding is not a rate limiter"],
		["a CACHE that is not a cache", { CACHE: wrong<SshCaBindings["CACHE"]>({}) }, "the CACHE binding is not a cache"],
		["an ISSUER_DN with a newline", { ISSUER_DN: "ssh ca\nsecond line" }, "ISSUER_DN contains control characters"],
		["ADMIN_ALLOWED_ROLES without ADMIN_JWT_ROLES_CLAIM", { ...admin, ADMIN_ALLOWED_ROLES: "admins" }, "ADMIN_ALLOWED_ROLES is set without ADMIN_JWT_ROLES_CLAIM"],
		["ADMIN_JWT_ROLES_CLAIM without ADMIN_ALLOWED_ROLES", { ...admin, ADMIN_JWT_ROLES_CLAIM: "groups" }, "ADMIN_JWT_ROLES_CLAIM is set without ADMIN_ALLOWED_ROLES"],
		["JWT_ACCESS_TOKEN_AUD with OIDC_USERINFO_URL", { JWT_ACCESS_TOKEN_AUD: "access", OIDC_USERINFO_URL: "https://idp.example.com/userinfo" }, "JWT_ACCESS_TOKEN_AUD is set with OIDC_USERINFO_URL"],
	])("should warn once about %s and still create the CA", (_name, overrides, warning) => {
		const env = valid(overrides)

		const warnings = warningsWhile(() => {
			createSshCa(env, { rateLimitKey: cloudflareClientIp })
			createSshCa(env, { rateLimitKey: cloudflareClientIp })
		})

		expect(warnings).toEqual([expect.stringContaining(warning)])
		expect(warnings[0]).toContain("will be refused in a future major release")
	})

	it("should not warn about admin roles when both settings are set", () => {
		expect(warningsWhile(() => createSshCa(valid({ ...admin, ADMIN_ALLOWED_ROLES: "admins", ADMIN_JWT_ROLES_CLAIM: "groups" })))).toEqual([])
	})

	it("should warn once on Workers, however many requests are served", async () => {
		const env = valid({ CACHE: wrong<SshCaBindings["CACHE"]>({}) })
		const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined, props: {} }
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		await ca.fetch(new Request("http://example.com/api/v4/ca"), env, ctx)
		await ca.fetch(new Request("http://example.com/api/v4/ca"), env, ctx)

		const warnings = log.mock.calls.flatMap(([entry]) => messageAt("warning", entry) ?? [])
		expect(warnings).toEqual([expect.stringContaining("the CACHE binding is not a cache")])
	})
})

describe("the Workers scheduled cleanup", () => {
	it("should warn once and run the cleanup when the configuration is valid", async () => {
		const sqlite = new DatabaseSync(":memory:")
		const env = valid({ DB: fromNodeSqlite(sqlite), CACHE: wrong<SshCaBindings["CACHE"]>({}) })
		const waited: Promise<unknown>[] = []
		const ctx = { waitUntil: (promise: Promise<unknown>) => { waited.push(promise) }, passThroughOnException: () => undefined, props: {} }
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)

		await ca.scheduled(undefined, env, ctx)
		await ca.scheduled(undefined, env, ctx)
		await Promise.all(waited)

		expect(log.mock.calls.flatMap(([entry]) => messageAt("warning", entry) ?? [])).toEqual([expect.stringContaining("the CACHE binding is not a cache")])
		expect(waited).toHaveLength(2)
		// the cleanup ran, so the database was migrated
		expect(sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'certificates'").get()).toBeDefined()
	})
})

describe("a missing DB binding", () => {
	// vitest fails the run on an unhandled rejection, which is how a missing
	// DB used to crash Node.js
	it("should answer a request that needs the database with a 500 and log why", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const response = await createSshCa(valid({ DB: wrong<SshCaBindings["DB"]>(undefined), LOG_LEVEL: "error" })).fetch(new Request("http://example.com/api/v4/host/krl"))

		expect(response.status).toBe(500)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: "error connecting to database" }))
	})
})
