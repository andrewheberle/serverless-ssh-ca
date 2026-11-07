import { describe, expect, it } from "vitest"
import { DatabaseSync } from "node:sqlite"
import ca, { createSshCa, InvalidConfigurationError, type SshCa, type SshCaBindings } from "../src/index.js"
import { LandingStylesheet, LandingStylesheetPath } from "../src/landing/pages.js"
import { assetHash } from "../src/web/assets.js"
import { SecurityHeaders } from "../src/web/headers.js"
import { bindingsFromEnv, fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { getPublic } from "../src/utils.js"
import { makeEnv } from "./env.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const Origin = "https://ssh-ca.example.com"

// the settings of an admin UI that is turned on. The landing page never
// fetches the JWKS, so it need not be served
const adminSettings: Partial<SshCaBindings> = {
	ADMIN_JWT_HEADER: "Cf-Access-Jwt-Assertion",
	ADMIN_JWKS_URL: "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
	ADMIN_JWT_ISSUER: "https://team.cloudflareaccess.com",
	ADMIN_JWT_AUD: "admin-aud-tag",
	ADMIN_ALLOWED_EMAILS: "admin@example.com",
}

const landingEnv = (overrides: Partial<SshCaBindings> = {}): SshCaBindings => makeEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey),
	LANDING_PAGE: "true",
	...overrides,
})

const landingCa = (overrides: Partial<SshCaBindings> = {}): SshCa => createSshCa(landingEnv(overrides))

const get = async (instance: SshCa, path: string, method = "GET"): Promise<Response> => await instance.fetch(new Request(`${Origin}${path}`, { method }))

const page = async (instance: SshCa): Promise<string> => {
	const response = await get(instance, "/")
	expect(response.status).toBe(200)

	return await response.text()
}

const expectSecurityHeaders = (response: Response): void => {
	for (const [name, value] of Object.entries(SecurityHeaders)) {
		expect(response.headers.get(name), name).toBe(value)
	}
}

// an execution context for the Workers default export
const executionContext = { waitUntil: () => undefined, passThroughOnException: () => undefined, props: {} }

describe("landing page configuration", () => {
	it.each([
		["not set", undefined],
		["false", false],
		["\"false\"", "false"],
	])("should answer / and its stylesheet with 404 when LANDING_PAGE is %s", async (_name, value) => {
		const instance = landingCa({ LANDING_PAGE: value })

		expect((await get(instance, "/")).status).toBe(404)
		expect((await get(instance, LandingStylesheetPath)).status).toBe(404)
		// the rest of the CA is unaffected
		expect((await get(instance, "/api/v4/ca")).status).toBe(200)
	})

	it.each([true, "true"])("should serve the landing page when LANDING_PAGE is %j", async (value) => {
		expect((await get(landingCa({ LANDING_PAGE: value }), "/")).status).toBe(200)
	})

	it("should refuse an invalid LANDING_PAGE in createSshCa", () => {
		expect(() => landingCa({ LANDING_PAGE: "yes" })).toThrow(InvalidConfigurationError)
		expect(() => landingCa({ LANDING_PAGE: "yes" })).toThrow(/LANDING_PAGE/)
	})

	it("should answer every request with 500 from the Workers default export when LANDING_PAGE is invalid", async () => {
		const env = landingEnv({ LANDING_PAGE: "yes" })

		for (const path of ["/", LandingStylesheetPath, "/api/v4/ca"]) {
			const response = await ca.fetch(new Request(`${Origin}${path}`), env, executionContext)
			expect(response.status, path).toBe(500)
			expect(await response.text()).not.toContain("LANDING_PAGE")
		}
	})

	it("should refuse an invalid LANDING_PAGE in bindingsFromEnv", () => {
		const source = {
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
		const bindings = { DB: fromNodeSqlite(new DatabaseSync(":memory:")), PRIVATE_KEY: secretFromString("key") }

		expect(bindingsFromEnv(bindings, { ...source, LANDING_PAGE: "true" }).LANDING_PAGE).toBe("true")
		expect(() => bindingsFromEnv(bindings, { ...source, LANDING_PAGE: "yes" })).toThrow(InvalidConfigurationError)
		expect(() => bindingsFromEnv(bindings, { ...source, LANDING_PAGE: "yes" })).toThrow(/LANDING_PAGE/)
	})
})

describe("landing page", () => {
	it("should show the CA public key and its fingerprint", async () => {
		const env = landingEnv()
		const publicKey = await getPublic(env)
		const response = await createSshCa(env).fetch(new Request(`${Origin}/`))

		expect(response.status).toBe(200)
		expect(response.headers.get("Content-Type")).toMatch(/^text\/html/)
		const body = await response.text()
		expect(body.startsWith("<!DOCTYPE html>")).toBe(true)
		expect(body).toContain(publicKey.toString())
		expect(body).toContain(publicKey.fingerprint())
		expect(body).toContain("href=\"/api/v4/ca\"")
	})

	it("should fill in the origin it was requested on in the snippets", async () => {
		const body = await page(landingCa())

		expect(body).toContain(`curl -fsS ${Origin}/api/v4/ca | sudo tee /etc/ssh/ca.pub`)
		expect(body).toContain(`${Origin}/api/v4/user/krl`)
		expect(body).toContain(`${Origin}/api/v4/host/krl`)
	})

	it("should link to the API docs, the KRLs and ssh-ca-client", async () => {
		const body = await page(landingCa())

		for (const href of ["/docs", "/api/v4/ca", "/api/v4/user/krl", "/api/v4/host/krl", "https://github.com/andrewheberle/ssh-ca-client", "https://github.com/andrewheberle/ssh-ca-client/releases"]) {
			expect(body, href).toContain(`href="${href}"`)
		}
	})

	it("should call the key the CA public key, never a CA certificate", async () => {
		const body = await page(landingCa())

		expect(body).toContain("CA public key")
		expect(body).not.toMatch(/CA certificate|root certificate/i)
	})

	it("should answer HEAD / without a body", async () => {
		const response = await get(landingCa(), "/", "HEAD")

		expect(response.status).toBe(200)
		expect(await response.text()).toBe("")
	})

	it("should answer POST / with 404", async () => {
		expect((await get(landingCa(), "/", "POST")).status).toBe(404)
	})

	it("should link its stylesheet, named after a hash of its content", async () => {
		expect(LandingStylesheetPath).toMatch(/^\/style-[0-9a-f]{8}\.css$/)
		expect(LandingStylesheetPath).toBe(`/style-${assetHash(LandingStylesheet)}.css`)
		expect(await page(landingCa())).toContain(`<link rel="stylesheet" href="${LandingStylesheetPath}"/>`)
	})

	it("should serve its stylesheet as CSS", async () => {
		const response = await get(landingCa(), LandingStylesheetPath)

		expect(response.status).toBe(200)
		expect(response.headers.get("Content-Type")).toBe("text/css; charset=utf-8")
		expect(await response.text()).toBe(LandingStylesheet)
	})

	it("should send the security headers with /", async () => {
		const response = await get(landingCa(), "/")

		expectSecurityHeaders(response)
		// the landing page has no client-side JavaScript
		expect(response.headers.get("Content-Security-Policy")).not.toContain("script-src")
	})

	it("should send the security headers with its stylesheet, which anyone may cache for a year", async () => {
		const response = await get(landingCa(), LandingStylesheetPath)

		for (const [name, value] of Object.entries(SecurityHeaders)) {
			expect(response.headers.get(name), name).toBe(name === "Cache-Control" ? "public, max-age=31536000, immutable" : value)
		}
	})

	it.each(["/style.css", "/style-00000000.css"])("should answer %s, which is not the current name of its stylesheet, with 404", async (path) => {
		expect((await get(landingCa(), path)).status).toBe(404)
	})

	it("should escape values that contain HTML", async () => {
		// the CA public key's comment is ISSUER_DN
		const body = await page(landingCa({ ISSUER_DN: "CN=<script>alert(1)</script>" }))

		expect(body).not.toContain("<script>")
		expect(body).toContain("CN=&lt;script&gt;alert(1)&lt;/script&gt;")
	})

	it("should not show the identity provider's or the allowlists' settings", async () => {
		const settings: Partial<SshCaBindings> = {
			JWT_ISSUER: "https://leak-check-issuer.example.net",
			JWT_AUD: "leak-check-client-id",
			JWT_ACCESS_TOKEN_AUD: "http://localhost:3000/leak-check-callback",
			SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: "leak-check-host-email@example.net",
			SSH_HOST_CERTIFICATE_ALLOWED_ROLES: "leak-check-host-role",
			ADMIN_ALLOWED_EMAILS: "leak-check-admin-email@example.net",
			ADMIN_ALLOWED_ROLES: "leak-check-admin-role",
			ADMIN_JWT_ROLES_CLAIM: "leak-check-roles-claim",
		}
		const body = await page(landingCa({ ...adminSettings, ...settings }))

		expect(body).not.toContain("leak-check")
		expect(body).not.toContain(adminSettings.ADMIN_JWT_AUD)
		expect(body).not.toContain(adminSettings.ADMIN_JWT_ISSUER)
	})
})

describe("landing page admin link", () => {
	it("should not link to the admin UI while it is turned off", async () => {
		const body = await page(landingCa())

		expect(body).not.toContain("Admin UI")
		expect(body).not.toContain("/admin")
	})

	it("should not link to the admin UI while it is partly configured", async () => {
		const body = await page(landingCa({ ...adminSettings, ADMIN_JWKS_URL: undefined }))

		expect(body).not.toContain("Admin UI")
		expect(body).not.toContain("/admin")
	})

	it("should link to /admin while the admin UI is turned on", async () => {
		expect(await page(landingCa(adminSettings))).toContain("<a href=\"/admin\">Admin UI</a>")
	})

	it("should link to the admin host name when the admin UI is limited to one", async () => {
		const body = await page(landingCa({ ...adminSettings, ADMIN_HOSTNAME: "Admin.Example.com" }))

		expect(body).toContain("<a href=\"https://admin.example.com/admin\">Admin UI</a>")
	})
})

describe("landing page routes", () => {
	it("should not shadow the rest of the CA", async () => {
		const off = landingCa({ LANDING_PAGE: undefined })
		const on = landingCa()

		for (const path of ["/docs", "/openapi.json", "/api/v4/ca", "/api/v4/user/krl", "/api/v4/host/krl", "/admin", "/admin/style.css", "/other", "/style.css/other"]) {
			const before = await get(off, path)
			const after = await get(on, path)
			expect(after.status, path).toBe(before.status)
			expect(after.headers.get("Content-Type"), path).toBe(before.headers.get("Content-Type"))
		}

		expect(await (await get(on, "/openapi.json")).text()).toBe(await (await get(off, "/openapi.json")).text())
		expect(await (await get(on, "/api/v4/ca")).text()).toBe(await (await get(off, "/api/v4/ca")).text())
	})

	it("should not add the security headers to the rest of the CA", async () => {
		const response = await get(landingCa(), "/api/v4/ca")

		expect(response.headers.get("Content-Security-Policy")).toBeNull()
	})

	it("should serve the admin UI as before while it is turned on", async () => {
		// without a proxy JWT the admin UI refuses the request, as it does
		// without the landing page
		expect((await get(landingCa(adminSettings), "/admin")).status).toBe(401)
	})
})
