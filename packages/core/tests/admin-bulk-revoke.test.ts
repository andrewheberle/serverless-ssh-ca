import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { cloudflareClientIp, createSshCa, type CaRateLimiter, type SshCa, type SshCaBindings } from "../src/index.js"
import { AdminSecurityHeaders } from "../src/admin/index.js"
import { CertificatePageSize, getKrlRevision, revokeCertificates } from "../src/db/index.js"
import { migrateOnce } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"
import { CertificateType } from "../src/db/types.js"
import { fromNodeSqlite } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { createProxy, type Proxy } from "./helpers/proxy.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const Header = "Cf-Access-Jwt-Assertion"
const AdminEmail = "Admin@Example.com"
const Origin = "https://ssh-ca.example.com"
const HourMs = 60 * 60 * 1000

let proxy: Proxy

beforeAll(async () => {
	proxy = await createProxy("admin-bulk-revoke-tests")
})

beforeEach(() => {
	proxy.serveJwks()
})

afterEach(() => {
	vi.restoreAllMocks()
})

/** A certificate to record directly in the database */
type Seed = {
	type?: CertificateType
	keyId?: string
	principals?: string
	/** Hours from now that the certificate expires, which is in the past when negative */
	expiresIn?: number
	revoked?: boolean
}

type Recorded = { revoked_at: string | null, revoked_by: string | null, revocation_reason: string | null }

// a CA whose admin UI is turned on, with an in-memory database that
// certificates can be recorded in directly
const setup = async (overrides: Partial<SshCaBindings> = {}) => {
	const sqlite = new DatabaseSync(":memory:")
	const env = makeEnv({
		DB: fromNodeSqlite(sqlite),
		PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey),
		ADMIN_JWT_HEADER: Header,
		ADMIN_JWKS_URL: proxy.jwksUrl,
		ADMIN_JWT_ISSUER: proxy.issuer,
		ADMIN_JWT_AUD: proxy.audience,
		ADMIN_ALLOWED_EMAILS: "admin@example.com",
		...overrides,
	})
	await migrateOnce(env.DB, migrations)

	let next = 1
	const insert = sqlite.prepare(`INSERT INTO certificates
		(serial, key_id, principals, extensions, valid_after, valid_before, revoked_at, certificate_type, public_key, requested_by, revoked_by, revocation_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)

	// records certificates in order, so later ones are newer, and returns their serials
	const seed = (...seeds: Seed[]): string[] => seeds.map((s) => {
		const serial = `${1000 + next++}`
		const now = Date.now()
		insert.run(
			serial,
			s.keyId ?? "alice@example.com",
			s.principals ?? (s.type === CertificateType.Host ? "CN=host.example.com" : "UID=alice"),
			"permit-pty",
			new Date(now - 2 * HourMs).toISOString(),
			new Date(now + (s.expiresIn ?? 24) * HourMs).toISOString(),
			s.revoked === true ? new Date(now - HourMs).toISOString() : null,
			s.type ?? CertificateType.User,
			ecdsaKey.user().publicKey,
			"alice@example.com",
			s.revoked === true ? "key-holder" : null,
			null,
		)
		return serial
	})

	const recorded = (serial: string): Recorded | undefined => sqlite.prepare("SELECT revoked_at, revoked_by, revocation_reason FROM certificates WHERE serial = ?")
		.get(serial) as Recorded | undefined
	const ca = createSshCa(env, overrides.RATE_LIMITER === undefined ? {} : { rateLimitKey: cloudflareClientIp })

	return { ca, env, sqlite, seed, recorded }
}

const get = async (ca: SshCa, path: string): Promise<Response> => await ca.fetch(new Request(`${Origin}${path}`, {
	headers: { [Header]: await proxy.sign({ email: AdminEmail }) },
}))

// a POST of the bulk revoke form that passes the checks against cross-site requests
const bulkRevoke = async (ca: SshCa, form: [string, string][], options: { kind?: string, headers?: Record<string, string>, email?: string } = {}): Promise<Response> => {
	const sent: Record<string, string> = {
		[Header]: await proxy.sign({ email: options.email ?? AdminEmail }),
		"Origin": Origin,
		"Sec-Fetch-Site": "same-origin",
		"Content-Type": "application/x-www-form-urlencoded",
		...options.headers,
	}

	// an empty value leaves the header out
	return await ca.fetch(new Request(`${Origin}/admin/${options.kind ?? "user"}/certificates/revoke`, {
		method: "POST",
		headers: Object.fromEntries(Object.entries(sent).filter(([, value]) => value !== "")),
		body: new URLSearchParams(form).toString(),
	}))
}

// the form fields that select serials, with a reason and the confirmation
const selected = (serials: string[], reason = "Offboarding", confirm = "yes"): [string, string][] => [
	...serials.map((s): [string, string] => ["serial", s]),
	["reason", reason],
	["confirm", confirm],
]

// the serials ticked on a confirmation page, in the order they are shown
const tickedSerials = (body: string): string[] => [...body.matchAll(/<input type="checkbox" name="serial" value="(\d+)" checked=""/g)].map((m) => m[1] ?? "")

// the link from a list page to its bulk revocation, if it has one
const bulkLink = (body: string): string | undefined => /<a class="button danger" href="([^"]+)">Revoke these certificates/.exec(body)?.[1]?.replaceAll("&amp;", "&")

describe("bulk revocation operation", () => {
	it("should revoke every valid certificate it is given, with one KRL revision", async () => {
		const { env, seed, recorded } = await setup()
		const serials = seed({}, {}, {})

		const results = await revokeCertificates(env, { serials: serials.map(BigInt), certificateType: CertificateType.User, email: AdminEmail, reason: "Offboarding" })

		expect(results.map((r) => [`${r.serial}`, r.result.kind])).toEqual(serials.map((s) => [s, "revoked"]))
		for (const serial of serials) {
			expect(recorded(serial)).toMatchObject({ revoked_by: AdminEmail, revocation_reason: "Offboarding" })
		}
		expect(await getKrlRevision(env, CertificateType.User)).toBe(1n)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)
	})

	it("should report each certificate it could not revoke, and revoke the rest", async () => {
		const { env, seed, recorded } = await setup()
		const [valid, revoked, expired, host] = seed({}, { revoked: true }, { expiresIn: -1 }, { type: CertificateType.Host })
		const before = recorded(revoked ?? "")

		const results = await revokeCertificates(env, {
			serials: [valid, revoked, expired, host, "999999"].map((s) => BigInt(s ?? "")),
			certificateType: CertificateType.User,
			email: AdminEmail,
			reason: "Offboarding",
		})

		expect(results.map((r) => r.result.kind)).toEqual(["revoked", "alreadyRevoked", "expired", "notFound", "notFound"])
		expect(recorded(revoked ?? "")).toEqual(before)
		expect(recorded(expired ?? "")?.revoked_at).toBeNull()
		expect(recorded(host ?? "")?.revoked_at).toBeNull()
		expect(await getKrlRevision(env, CertificateType.User)).toBe(1n)
	})

	it("should not change the KRL revision when it revokes nothing", async () => {
		const { env, seed } = await setup()
		const serials = seed({ revoked: true }, { expiresIn: -1 })

		const results = await revokeCertificates(env, { serials: serials.map(BigInt), certificateType: CertificateType.User, email: AdminEmail, reason: "Offboarding" })

		expect(results.map((r) => r.result.kind)).toEqual(["alreadyRevoked", "expired"])
		expect(await getKrlRevision(env, CertificateType.User)).toBe(0n)
	})

	it("should revoke a serial given twice once", async () => {
		const { env, seed } = await setup()
		const [serial] = seed({})

		const results = await revokeCertificates(env, { serials: [BigInt(serial ?? ""), BigInt(serial ?? "")], certificateType: CertificateType.User, email: AdminEmail, reason: "Offboarding" })

		expect(results.map((r) => r.result.kind)).toEqual(["revoked"])
	})

	it("should refuse more certificates than a page", async () => {
		const { env } = await setup()
		const serials = Array.from({ length: CertificatePageSize + 1 }, (_, i) => BigInt(i + 1))

		await expect(revokeCertificates(env, { serials, certificateType: CertificateType.User, email: AdminEmail, reason: "Offboarding" })).rejects.toThrow(RangeError)
	})

	it("should write an audit log line for each certificate it revokes", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const { env, seed } = await setup({ LOG_LEVEL: "info" })
		const [first, second, revoked] = seed({}, {}, { revoked: true })

		await revokeCertificates(env, { serials: [first, second, revoked].map((s) => BigInt(s ?? "")), certificateType: CertificateType.User, email: AdminEmail, reason: "Offboarding" })

		const lines = log.mock.calls.map(([line]: unknown[]) => line).filter((line) => typeof line === "object" && line !== null && "message" in line && line.message === "certificate revoked")
		expect(lines).toEqual([first, second].map((serial) => expect.objectContaining({ serial, certificate_type: "user", revoked_by: AdminEmail, revocation_reason: "Offboarding" })))
	})
})

describe("bulk revocation in the admin UI", () => {
	it("should link a list filtered to valid certificates by key ID or principal to its bulk revocation", async () => {
		const { ca, seed } = await setup()
		seed({})

		expect(bulkLink(await (await get(ca, "/admin/user/certificates?key_id=alice")).text())).toBe("/admin/user/certificates/revoke?status=valid&key_id=alice")
		expect(bulkLink(await (await get(ca, "/admin/user/certificates?principal=alice")).text())).toBe("/admin/user/certificates/revoke?status=valid&principal=alice")
	})

	it.each([
		["no filter", "/admin/user/certificates"],
		["only a serial filter", "/admin/user/certificates?serial=1001"],
		["a status other than valid", "/admin/user/certificates?status=all&key_id=alice"],
		["no matching certificates", "/admin/user/certificates?key_id=bob"],
	])("should not link a list with %s to a bulk revocation", async (_name, path) => {
		const { ca, seed } = await setup()
		seed({})

		expect(bulkLink(await (await get(ca, path)).text())).toBeUndefined()
	})

	it("should list the matching valid certificates, newest first and all ticked, with their key IDs", async () => {
		const { ca, seed } = await setup()
		const [older, , newer] = seed({ keyId: "alice@example.com" }, { keyId: "bob@example.com" }, { keyId: "malice@example.com" })
		seed({ keyId: "alice@example.com", revoked: true }, { keyId: "alice@example.com", expiresIn: -1 })

		const response = await get(ca, "/admin/user/certificates/revoke?key_id=alice")

		expect(response.status).toBe(200)
		const body = await response.text()
		expect(tickedSerials(body)).toEqual([newer, older])
		expect(body).toContain("<td>malice@example.com</td>")
		expect(body).toContain("<form class=\"revoke\" method=\"post\" action=\"/admin/user/certificates/revoke\">")
		expect(body).toContain("<input type=\"hidden\" name=\"key_id\" value=\"alice\"")
		expect(body).not.toContain("more than")
	})

	it("should list at most a page of certificates and say that more remain", async () => {
		const { ca, seed } = await setup()
		const serials = seed(...Array.from({ length: CertificatePageSize + 2 }, (): Seed => ({})))

		const body = await (await get(ca, "/admin/user/certificates/revoke?principal=alice")).text()

		expect(tickedSerials(body)).toEqual(serials.slice(2).reverse())
		expect(body).toContain(`More than ${CertificatePageSize} certificates match`)
	})

	it.each([
		["no filter", "/admin/user/certificates/revoke", 400],
		["only a serial filter", "/admin/user/certificates/revoke?serial=1001", 400],
		["a status other than valid", "/admin/user/certificates/revoke?status=all&key_id=alice", 400],
		["an invalid filter", "/admin/user/certificates/revoke?principal=a,b", 400],
		["an unknown kind", "/admin/other/certificates/revoke?key_id=alice", 404],
	])("should refuse a bulk revocation page with %s", async (_name, path, status) => {
		const { ca, seed } = await setup()
		seed({})

		const response = await get(ca, path)
		expect(response.status).toBe(status)
		expect(tickedSerials(await response.text())).toEqual([])
	})

	it("should revoke the selected certificates and show what happened to each", async () => {
		const { ca, env, seed, recorded } = await setup()
		const [first, second, unticked, revoked] = seed({}, {}, {}, { revoked: true })

		const response = await bulkRevoke(ca, [...selected([first, second, revoked].map((s) => s ?? ""), "  Left the company \n"), ["key_id", "alice"]])

		expect(response.status).toBe(200)
		const body = await response.text()
		for (const serial of [first, second]) {
			expect(recorded(serial ?? "")).toMatchObject({ revoked_by: AdminEmail, revocation_reason: "Left the company" })
			expect(body).toContain(`<a class="mono" href="/admin/user/certificates/${serial}">${serial}</a></td><td><span class="badge revoked">Revoked</span>`)
		}
		expect(body).toContain(`<a class="mono" href="/admin/user/certificates/${revoked}">${revoked}</a></td><td><span class="badge expired">Already revoked</span>`)
		expect(body).toContain("Revoked 2 of 3 certificates")
		expect(body).toContain("href=\"/admin/user/certificates?status=valid&amp;key_id=alice\"")
		expect(recorded(unticked ?? "")?.revoked_at).toBeNull()
		expect(await getKrlRevision(env, CertificateType.User)).toBe(1n)
	})

	it("should revoke host certificates from the host list", async () => {
		const { ca, env, seed, recorded } = await setup()
		const [host] = seed({ type: CertificateType.Host })

		expect((await bulkRevoke(ca, selected([host ?? ""]), { kind: "host" })).status).toBe(200)
		expect(recorded(host ?? "")?.revoked_by).toBe(AdminEmail)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
		expect(await getKrlRevision(env, CertificateType.User)).toBe(0n)
	})

	it.each([
		["no reason", (s: string[]) => selected(s, ""), "Give a reason for revoking the certificate."],
		["a reason over 500 characters", (s: string[]) => selected(s, "a".repeat(501)), "The reason must be at most 500 characters."],
		["an unticked confirmation", (s: string[]) => selected(s, "Offboarding", "no"), "Tick the box to confirm that the revocation cannot be undone."],
		["no certificates selected", () => selected([]), "Select at least one certificate to revoke."],
		["a serial that is not a number", (s: string[]) => selected([...s, "abc"]), "A selected certificate is not a valid serial number."],
		["too many certificates", (s: string[]) => selected([...s, ...Array.from({ length: CertificatePageSize }, (_, i) => `${i + 1}`)]), `At most ${CertificatePageSize} certificates can be revoked at once.`],
	])("should show the confirmation again with a 422 for %s, and revoke nothing", async (_name, form, error) => {
		const { ca, env, seed, recorded } = await setup()
		const serials = seed({}, {})

		const response = await bulkRevoke(ca, form(serials))

		expect(response.status).toBe(422)
		const body = await response.text()
		expect(body).toContain(`<li>${error}</li>`)
		expect(body).toContain("<form class=\"revoke\"")
		for (const serial of serials) {
			expect(recorded(serial)?.revoked_at).toBeNull()
		}
		expect(await getKrlRevision(env, CertificateType.User)).toBe(0n)
	})

	it("should list only the posted certificates, and keep the reason, when it shows the confirmation again", async () => {
		const { ca, seed } = await setup()
		const [first, second, unticked] = seed({}, {}, {})

		const body = await (await bulkRevoke(ca, selected([first ?? "", second ?? ""], "</textarea><script>alert(1)</script>", "no"))).text()

		expect(tickedSerials(body)).toEqual([second, first])
		expect(body).not.toContain(`value="${unticked}"`)
		expect(body).not.toContain("<script>alert")
		expect(body).toContain("&lt;/textarea&gt;&lt;script&gt;alert(1)&lt;/script&gt;</textarea>")
	})

	it.each([
		["another Origin", { "Origin": "https://evil.example.com" }],
		["no Origin", { "Origin": "" }],
		["no Sec-Fetch-Site", { "Sec-Fetch-Site": "" }],
		["a cross-site Sec-Fetch-Site", { "Sec-Fetch-Site": "cross-site" }],
	])("should refuse a bulk revocation with %s and revoke nothing", async (_name, headers) => {
		const { ca, seed, recorded } = await setup()
		const serials = seed({}, {})

		const response = await bulkRevoke(ca, selected(serials), { headers })

		expect(response.status).toBe(403)
		for (const [name, value] of Object.entries(AdminSecurityHeaders)) {
			expect(response.headers.get(name), name).toBe(value)
		}
		for (const serial of serials) {
			expect(recorded(serial)?.revoked_at).toBeNull()
		}
	})

	it("should refuse someone who is not an admin, and revoke nothing", async () => {
		const { ca, seed, recorded } = await setup()
		const [serial] = seed({})

		expect((await bulkRevoke(ca, selected([serial ?? ""]), { email: "someone@example.com" })).status).toBe(403)
		expect(recorded(serial ?? "")?.revoked_at).toBeNull()
	})

	it("should count a bulk revocation as one request against the admin's rate limit", async () => {
		const keys: string[] = []
		const limiter: CaRateLimiter = { limit: async ({ key }) => { keys.push(key); return { success: false } } }
		const { ca, seed, recorded } = await setup({ RATE_LIMITER: limiter })
		const serials = seed({}, {})

		const response = await bulkRevoke(ca, selected(serials))

		expect(response.status).toBe(429)
		expect(keys).toEqual([`admin:${AdminEmail}`])
		for (const serial of serials) {
			expect(recorded(serial)?.revoked_at).toBeNull()
		}
	})

	it("should still show a certificate's detail page", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({})

		const response = await get(ca, `/admin/user/certificates/${serial}`)
		expect(response.status).toBe(200)
		expect(await response.text()).toContain(`<form class="revoke" method="post" action="/admin/user/certificates/${serial}/revoke">`)
	})
})
