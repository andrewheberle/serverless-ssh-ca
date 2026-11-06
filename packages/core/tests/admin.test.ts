import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import ca, { cloudflareClientIp, createSshCa, InvalidConfigurationError, type CaRateLimiter, type SshCa, type SshCaBindings } from "../src/index.js"
import { AdminSecurityHeaders } from "../src/admin/index.js"
import { bindingsFromEnv, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { createProxy, type Proxy } from "./helpers/proxy.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const Header = "Cf-Access-Jwt-Assertion"
const AdminEmail = "Admin@Example.com"
const AdminRole = "ssh-ca-admin"
const Origin = "https://ssh-ca.example.com"

let proxy: Proxy

beforeAll(async () => {
	proxy = await createProxy("admin-tests")
})

beforeEach(() => {
	proxy.serveJwks()
})

afterEach(() => {
	vi.restoreAllMocks()
})

// the admin settings of a CA whose admin UI is turned on
const adminSettings = (): Partial<SshCaBindings> => ({
	ADMIN_JWT_HEADER: Header,
	ADMIN_JWKS_URL: proxy.jwksUrl,
	ADMIN_JWT_ISSUER: proxy.issuer,
	ADMIN_JWT_AUD: proxy.audience,
	ADMIN_ALLOWED_EMAILS: AdminEmail,
	ADMIN_ALLOWED_ROLES: AdminRole,
	ADMIN_JWT_ROLES_CLAIM: "groups",
})

const adminEnv = (overrides: Partial<SshCaBindings> = {}): SshCaBindings => makeEnv({
	PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey),
	...adminSettings(),
	...overrides,
})

const adminCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(adminEnv(overrides))

// a request for the admin UI, with a proxy JWT unless one is given
const request = async (path: string, options: { jwt?: string | null, method?: string, headers?: Record<string, string>, body?: string, origin?: string } = {}): Promise<Request> => {
	const jwt = options.jwt === undefined ? await proxy.sign({ email: AdminEmail }) : options.jwt
	return new Request(`${options.origin ?? Origin}${path}`, {
		method: options.method ?? "GET",
		headers: { ...(jwt === null ? {} : { [Header]: jwt }), ...options.headers },
		body: options.body,
	})
}

// a POST that passes every check against cross-site requests
const sameOriginPost = async (path: string, jwt?: string): Promise<Request> => await request(path, {
	method: "POST",
	jwt,
	headers: { "Origin": Origin, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded" },
	body: "a=b",
})

const expectSecurityHeaders = (response: Response): void => {
	for (const [name, value] of Object.entries(AdminSecurityHeaders)) {
		expect(response.headers.get(name), name).toBe(value)
	}
}

// an execution context for the Workers default export
const executionContext = { waitUntil: () => undefined, passThroughOnException: () => undefined, props: {} }

describe("admin configuration", () => {
	// settings that leave the admin UI partly configured, and what is missing
	const partial: [string, Partial<SshCaBindings>, string][] = [
		["no header", { ADMIN_JWT_HEADER: undefined }, "ADMIN_JWT_HEADER"],
		["no JWKS URL", { ADMIN_JWKS_URL: undefined }, "ADMIN_JWKS_URL"],
		["no issuer", { ADMIN_JWT_ISSUER: undefined }, "ADMIN_JWT_ISSUER"],
		["no audience", { ADMIN_JWT_AUD: undefined }, "ADMIN_JWT_AUD"],
		["an empty audience string", { ADMIN_JWT_AUD: "" }, "ADMIN_JWT_AUD"],
		["no allowlist", { ADMIN_ALLOWED_EMAILS: undefined, ADMIN_ALLOWED_ROLES: undefined, ADMIN_JWT_ROLES_CLAIM: undefined }, "ADMIN_ALLOWED_EMAILS or ADMIN_ALLOWED_ROLES with ADMIN_JWT_ROLES_CLAIM"],
		["roles without a claim", { ADMIN_ALLOWED_EMAILS: undefined, ADMIN_JWT_ROLES_CLAIM: undefined }, "ADMIN_JWT_ROLES_CLAIM"],
		["a roles claim without roles", { ADMIN_ALLOWED_EMAILS: undefined, ADMIN_ALLOWED_ROLES: undefined }, "ADMIN_ALLOWED_ROLES"],
	]

	it.each(partial)("should turn the admin UI off, with %s, and keep serving the client API", async (_name, overrides) => {
		vi.spyOn(console, "log").mockImplementation(() => undefined)
		const ca = adminCa(overrides)

		const response = await ca.fetch(await request("/admin"))
		expect(response.status).toBe(404)
		expectSecurityHeaders(response)
		expect((await ca.fetch(await request("/admin/style.css"))).status).toBe(404)

		expect((await ca.fetch(new Request(`${Origin}/api/v4/ca`))).status).toBe(200)
	})

	it.each(partial)("should warn once, with %s, naming what is missing", async (_name, overrides, missing) => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const env = adminEnv({ LOG_LEVEL: "warning", ...overrides })

		createSshCa(env)
		createSshCa(env)
		await ca.fetch(await request("/admin"), env, executionContext)
		await ca.fetch(await request("/admin"), env, executionContext)

		expect(log).toHaveBeenCalledTimes(1)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "warning", missing }))
	})

	it.each([
		["ADMIN_HOSTNAME", { ADMIN_HOSTNAME: "ssh-ca.example.com" }],
		["ADMIN_JWT_ALGORITHMS", { ADMIN_JWT_ALGORITHMS: "ES256" }],
		["ADMIN_ALLOWED_EMAILS", { ADMIN_ALLOWED_EMAILS: AdminEmail }],
	])("should count only %s being set as partly configured", async (_name, settings) => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const ca = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey), LOG_LEVEL: "warning", ...settings }))

		expect((await ca.fetch(await request("/admin"))).status).toBe(404)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "warning", missing: expect.stringContaining("ADMIN_JWT_HEADER") }))
	})

	it("should turn the admin UI off, without a warning, when no admin setting is set", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const ca = createSshCa(makeEnv({ PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey), LOG_LEVEL: "debug" }))

		const response = await ca.fetch(await request("/admin"))
		expect(response.status).toBe(404)
		expectSecurityHeaders(response)
		expect((await ca.fetch(new Request(`${Origin}/api/v4/ca`))).status).toBe(200)
		expect(log).not.toHaveBeenCalled()
	})

	// admin settings that are set but not valid, which make the whole
	// configuration invalid
	const invalid: [keyof SshCaBindings, string | string[]][] = [
		["ADMIN_JWT_HEADER", "Cf Access Jwt Assertion"],
		["ADMIN_JWKS_URL", "http://admin-tests.cloudflareaccess.com/cdn-cgi/access/certs"],
		["ADMIN_JWKS_URL", "not a url"],
		["ADMIN_JWT_ISSUER", " "],
		["ADMIN_JWT_AUD", ","],
		["ADMIN_JWT_AUD", []],
		["ADMIN_JWT_ALGORITHMS", "HS256"],
		["ADMIN_JWT_ALGORITHMS", "none"],
		["ADMIN_JWT_ALGORITHMS", "RS256,"],
		["ADMIN_ALLOWED_EMAILS", "admin@example.com,,other@example.com"],
		["ADMIN_ALLOWED_ROLES", " , "],
		["ADMIN_JWT_ROLES_CLAIM", " "],
		["ADMIN_HOSTNAME", "https://ssh-ca.example.com"],
		["ADMIN_HOSTNAME", "ssh-ca.example.com:8443"],
	]

	it.each(invalid)("should refuse %s of %j in createSshCa", (key, value) => {
		expect(() => adminCa({ [key]: value })).toThrow(InvalidConfigurationError)
		expect(() => adminCa({ [key]: value })).toThrow(key)
	})

	it.each(invalid)("should refuse %s of %j even when the admin UI is otherwise not configured", (key, value) => {
		expect(() => createSshCa(makeEnv({ [key]: value }))).toThrow(key)
	})

	it.each(invalid)("should answer every request with 500 from the Workers default export for %s of %j", async (key, value) => {
		vi.spyOn(console, "log").mockImplementation(() => undefined)
		const env = adminEnv({ [key]: value })

		for (const path of ["/admin", "/api/v4/ca"]) {
			const response = await ca.fetch(await request(path), env, executionContext)
			expect(response.status).toBe(500)
		}
	})

	it.each(invalid.filter((entry): entry is [keyof SshCaBindings, string] => typeof entry[1] === "string"))("should refuse %s of %j in bindingsFromEnv", (key, value) => {
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
			[key]: value,
		}
		const bindings = { DB: makeEnv().DB, PRIVATE_KEY: secretFromString("key") }

		expect(() => bindingsFromEnv(bindings, source)).toThrow(InvalidConfigurationError)
		expect(() => bindingsFromEnv(bindings, source)).toThrow(key)
	})

	it("should read the admin settings in bindingsFromEnv", async () => {
		const settings = { ...adminSettings(), ADMIN_JWT_ALGORITHMS: "RS256, ES256", ADMIN_HOSTNAME: "ssh-ca.example.com" }
		const env = bindingsFromEnv({ DB: makeEnv().DB, PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey) }, {
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
			LOG_LEVEL: "none",
			...Object.fromEntries(Object.entries(settings).map(([key, value]) => [key, String(value)])),
		})

		const response = await createSshCa(env).fetch(await request("/admin", { jwt: await proxy.sign({ email: AdminEmail }, { key: "es256" }) }))
		expect(response.status).toBe(200)
	})

	it("should treat empty admin variables in bindingsFromEnv as not set", () => {
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
			ADMIN_JWKS_URL: "",
			ADMIN_HOSTNAME: "",
		}

		expect(() => bindingsFromEnv({ DB: makeEnv().DB, PRIVATE_KEY: secretFromString("key") }, source)).not.toThrow()
	})
})

describe("admin UI", () => {
	it("should show who is signed in, with their email exactly as the proxy gives it", async () => {
		const response = await adminCa().fetch(await request("/admin"))

		expect(response.status).toBe(200)
		expect(response.headers.get("Content-Type")).toMatch(/^text\/html/)
		const body = await response.text()
		expect(body).toMatch(/^<!DOCTYPE html>/)
		expect(body).toContain(`Signed in as ${AdminEmail}`)
		expect(body).toContain(`<link rel="stylesheet" href="/admin/style.css"/>`)
	})

	it("should escape the email on the page", async () => {
		const jwt = await proxy.sign({ email: "<script>alert(1)</script>@example.com", groups: [AdminRole] })
		const body = await (await adminCa().fetch(await request("/admin", { jwt }))).text()

		expect(body).not.toContain("<script>")
		expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;@example.com")
	})

	it("should serve the stylesheet to admins", async () => {
		const ca = adminCa()

		const response = await ca.fetch(await request("/admin/style.css"))
		expect(response.status).toBe(200)
		expect(response.headers.get("Content-Type")).toBe("text/css; charset=utf-8")
		expectSecurityHeaders(response)

		expect((await ca.fetch(await request("/admin/style.css", { jwt: null }))).status).toBe(401)
	})

	it("should be served by the Workers default export", async () => {
		const response = await ca.fetch(await request("/admin"), adminEnv(), executionContext)
		expect(response.status).toBe(200)
	})

	it("should not answer paths that only start with /admin", async () => {
		expect((await adminCa().fetch(await request("/administrator"))).status).toBe(404)
	})
})

describe("admin hostname", () => {
	it("should answer on the configured host name, compared case-insensitively", async () => {
		const response = await adminCa({ ADMIN_HOSTNAME: "SSH-CA.example.com" }).fetch(await request("/admin"))
		expect(response.status).toBe(200)
	})

	it("should answer every other host name with 404", async () => {
		const ca = adminCa({ ADMIN_HOSTNAME: "ssh-ca.example.com" })

		for (const path of ["/admin", "/admin/style.css"]) {
			const response = await ca.fetch(await request(path, { origin: "https://ssh-ca.workers.dev" }))
			expect(response.status).toBe(404)
			expectSecurityHeaders(response)
		}

		// the client API is still served on every host name
		expect((await ca.fetch(new Request("https://ssh-ca.workers.dev/api/v4/ca"))).status).toBe(200)
	})
})

describe("admin authentication", () => {
	const unauthenticated: [string, () => Promise<string | null>][] = [
		["a missing JWT", async () => null],
		["an empty JWT", async () => ""],
		["a JWT that is not a JWT", async () => "not-a-jwt"],
		["a bad signature", async () => await proxy.sign({ email: AdminEmail }, { key: "unknown" })],
		["the wrong issuer", async () => await proxy.sign({ email: AdminEmail }, { issuer: "https://other.cloudflareaccess.com" })],
		["the wrong audience", async () => await proxy.sign({ email: AdminEmail }, { audience: "other-aud" })],
		["an algorithm that is not allowed", async () => await proxy.sign({ email: AdminEmail }, { key: "es256" })],
		["an expired JWT", async () => await proxy.sign({ email: AdminEmail }, { expires: Math.floor(Date.now() / 1000) - 60 })],
	]

	it.each(unauthenticated)("should refuse %s with 401", async (_name, jwt) => {
		const response = await adminCa().fetch(await request("/admin", { jwt: await jwt() }))

		expect(response.status).toBe(401)
		expectSecurityHeaders(response)
	})

	it("should accept the algorithms configured", async () => {
		const ca = adminCa({ ADMIN_JWT_ALGORITHMS: "ES256" })

		expect((await ca.fetch(await request("/admin", { jwt: await proxy.sign({ email: AdminEmail }, { key: "es256" }) }))).status).toBe(200)
		expect((await ca.fetch(await request("/admin", { jwt: await proxy.sign({ email: AdminEmail }) }))).status).toBe(401)
	})

	it("should accept any of several audiences", async () => {
		const ca = adminCa({ ADMIN_JWT_AUD: ["first-aud", proxy.audience] })
		expect((await ca.fetch(await request("/admin"))).status).toBe(200)
	})

	const forbidden: [string, Partial<SshCaBindings>, Record<string, unknown>][] = [
		["no email claim", {}, { groups: [AdminRole] }],
		["an empty email claim", {}, { email: " ", groups: [AdminRole] }],
		["an email claim that is not a string", {}, { email: ["admin@example.com"], groups: [AdminRole] }],
		["an email that is not allowed", {}, { email: "someone@example.com" }],
		["a role that is not allowed", {}, { email: "someone@example.com", groups: ["ssh-users"] }],
		["a role that only differs in case", {}, { email: "someone@example.com", groups: ["SSH-CA-ADMIN"] }],
		["an allowed role when roles are not configured", { ADMIN_ALLOWED_ROLES: undefined, ADMIN_JWT_ROLES_CLAIM: undefined }, { email: "someone@example.com", groups: [AdminRole] }],
		["an allowed role in another claim", {}, { email: "someone@example.com", roles: [AdminRole] }],
	]

	it.each(forbidden)("should refuse %s with 403", async (_name, overrides, claims) => {
		const response = await adminCa(overrides).fetch(await request("/admin", { jwt: await proxy.sign(claims) }))

		expect(response.status).toBe(403)
		expectSecurityHeaders(response)
	})

	const admins: [string, Partial<SshCaBindings>, Record<string, unknown>][] = [
		["an allowed email", {}, { email: AdminEmail }],
		["an allowed email in another case", {}, { email: "aDMIN@eXAMPLE.cOM" }],
		["an allowed email with emails listed in another case", { ADMIN_ALLOWED_EMAILS: "other@example.com, ADMIN@EXAMPLE.COM" }, { email: "admin@example.com" }],
		["an allowed role as a string", {}, { email: "someone@example.com", groups: AdminRole }],
		["an allowed role in an array", {}, { email: "someone@example.com", groups: ["ssh-users", AdminRole] }],
		["an allowed role with only roles configured", { ADMIN_ALLOWED_EMAILS: undefined }, { email: "someone@example.com", groups: [AdminRole] }],
		["an allowed email with a roles claim of the wrong type", {}, { email: AdminEmail, groups: 42 }],
	]

	it.each(admins)("should accept %s", async (_name, overrides, claims) => {
		const response = await adminCa(overrides).fetch(await request("/admin", { jwt: await proxy.sign(claims) }))

		expect(response.status).toBe(200)
	})

	it.each([
		["a number", 42],
		["an object", { role: AdminRole }],
		["an array with a value that is not a string", [AdminRole, 1]],
	])("should ignore a roles claim that is %s, with a warning naming the claim", async (_name, groups) => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const response = await adminCa({ LOG_LEVEL: "warning" }).fetch(await request("/admin", { jwt: await proxy.sign({ email: "someone@example.com", groups }) }))

		expect(response.status).toBe(403)
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "warning", claim: "groups" }))
	})
})

describe("admin cross-site requests", () => {
	it("should let a same-origin POST through to routing", async () => {
		const response = await adminCa().fetch(await sameOriginPost("/admin"))

		expect([404, 405]).toContain(response.status)
		expectSecurityHeaders(response)
	})

	const refused: [string, Record<string, string>][] = [
		["a POST from another origin", { "Origin": "https://evil.example.com", "Sec-Fetch-Site": "same-origin" }],
		["a POST from another origin as JSON", { "Origin": "https://evil.example.com", "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" }],
		["a POST without an Origin", { "Sec-Fetch-Site": "same-origin" }],
		["a POST without Sec-Fetch-Site", { "Origin": Origin }],
		["a cross-site POST", { "Origin": Origin, "Sec-Fetch-Site": "cross-site" }],
		["a same-site POST", { "Origin": Origin, "Sec-Fetch-Site": "same-site" }],
		["a POST with Sec-Fetch-Site none", { "Origin": Origin, "Sec-Fetch-Site": "none" }],
	]

	it.each(refused)("should refuse %s with 403", async (_name, headers) => {
		const response = await adminCa().fetch(await request("/admin", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
			body: "a=b",
		}))

		expect(response.status).toBe(403)
		expectSecurityHeaders(response)
	})

	it("should require the Origin of the configured host name", async () => {
		const ca = adminCa({ ADMIN_HOSTNAME: "ssh-ca.example.com" })
		const post = (origin: string) => request("/admin", {
			method: "POST",
			headers: { "Origin": origin, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded" },
			body: "a=b",
		})

		expect((await ca.fetch(await post("https://ssh-ca.example.com"))).status).toBe(404)
		expect((await ca.fetch(await post("http://ssh-ca.example.com"))).status).toBe(403)
	})

	it("should not check GET requests", async () => {
		const response = await adminCa().fetch(await request("/admin", { headers: { "Origin": "https://evil.example.com", "Sec-Fetch-Site": "cross-site" } }))
		expect(response.status).toBe(200)
	})
})

describe("admin rate limiting", () => {
	// a rate limiter that records the keys it is asked about
	const fakeLimiter = (success: boolean): CaRateLimiter & { keys: string[] } => {
		const keys: string[] = []
		return { keys, limit: async ({ key }) => { keys.push(key); return { success } } }
	}

	const limitedCa = (limiter: CaRateLimiter): SshCa => createSshCa(adminEnv({ RATE_LIMITER: limiter }), { rateLimitKey: cloudflareClientIp })

	it("should limit POSTs by the admin's email", async () => {
		const limiter = fakeLimiter(true)
		const jwt = await proxy.sign({ email: "someone@example.com", groups: [AdminRole] })

		const response = await limitedCa(limiter).fetch(await sameOriginPost("/admin", jwt))

		expect(response.status).not.toBe(429)
		expect(limiter.keys).toEqual(["admin:someone@example.com"])
	})

	it("should refuse a POST the rate limiter refuses with 429", async () => {
		const response = await limitedCa(fakeLimiter(false)).fetch(await sameOriginPost("/admin"))

		expect(response.status).toBe(429)
		expectSecurityHeaders(response)
	})

	it("should not limit GETs", async () => {
		const limiter = fakeLimiter(false)

		expect((await limitedCa(limiter).fetch(await request("/admin"))).status).toBe(200)
		expect(limiter.keys).toEqual([])
	})

	it("should not limit requests that are refused before the admin is known", async () => {
		const limiter = fakeLimiter(true)
		const ca = limitedCa(limiter)

		expect((await ca.fetch(await sameOriginPost("/admin", await proxy.sign({ email: "someone@example.com" })))).status).toBe(403)
		expect((await ca.fetch(await request("/admin", { method: "POST", headers: { "Origin": "https://evil.example.com" } }))).status).toBe(403)
		expect(limiter.keys).toEqual([])
	})
})

describe("admin logging", () => {
	it("should log every request with the admin's email, method, path and status", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const ca = adminCa({ LOG_LEVEL: "info" })

		await ca.fetch(await request("/admin?serial=1234&status=valid"))
		await ca.fetch(await request("/admin/style.css"))

		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "info", email: AdminEmail, method: "GET", path: "/admin?serial=1234&status=valid", status: 200 }))
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "info", email: AdminEmail, method: "GET", path: "/admin/style.css", status: 200 }))
	})

	it("should log refused requests", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const ca = adminCa({ LOG_LEVEL: "info" })

		await ca.fetch(await request("/admin", { jwt: null }))
		await ca.fetch(await request("/admin", { jwt: await proxy.sign({ email: "someone@example.com" }) }))

		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "info", method: "GET", path: "/admin", status: 401 }))
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "info", email: "someone@example.com", method: "GET", path: "/admin", status: 403 }))
	})

	it("should never log the JWT", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const ca = adminCa({ LOG_LEVEL: "debug" })
		const jwts = [
			await proxy.sign({ email: AdminEmail }),
			await proxy.sign({ email: AdminEmail }, { key: "unknown" }),
			await proxy.sign({ email: AdminEmail }, { expires: Math.floor(Date.now() / 1000) - 60 }),
			await proxy.sign({ email: "someone@example.com", groups: 42 }),
		]

		for (const jwt of jwts) {
			await ca.fetch(await request("/admin", { jwt }))
			await ca.fetch(await sameOriginPost("/admin", jwt))
		}

		expect(log).toHaveBeenCalled()
		const logged = JSON.stringify(log.mock.calls)
		for (const jwt of jwts) {
			expect(logged).not.toContain(jwt)
			// nor any part of it, such as its signature
			for (const part of jwt.split(".")) {
				expect(logged).not.toContain(part)
			}
		}
	})
})
