import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa, type SshCa, type SshCaBindings } from "../src/index.js"
import { AdminSecurityHeaders } from "../src/admin/index.js"
import { CertificateListQuery } from "../src/admin/query.js"
import { listCertificates } from "../src/db/index.js"
import { migrateOnce } from "../src/db/migrate.js"
import { migrations } from "../src/db/migrations/index.js"
import { CertificateType } from "../src/db/types.js"
import { fromNodeSqlite } from "../src/node/index.js"
import { PublicKey } from "../src/ssh/keys.js"
import { makeEnv } from "./env.js"
import { createProxy, type Proxy } from "./helpers/proxy.js"
import { MockSecretStore } from "./helpers/secret.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const Header = "Cf-Access-Jwt-Assertion"
const AdminEmail = "admin@example.com"
const Origin = "https://ssh-ca.example.com"
const HourMs = 60 * 60 * 1000

let proxy: Proxy

beforeAll(async () => {
	proxy = await createProxy("admin-certificates-tests")
})

beforeEach(() => {
	proxy.serveJwks()
})

afterEach(() => {
	vi.restoreAllMocks()
})

/** A certificate to record directly in the database, with the values a test cares about */
type Seed = {
	type?: CertificateType
	serial?: string
	keyId?: string
	principals?: string
	extensions?: string | null
	/** Hours from now that the certificate expires, which is in the past when negative */
	expiresIn?: number
	revoked?: { by: string | null, reason: string | null } | undefined
	publicKey?: string | null
	requestedBy?: string | null
}

// a CA whose admin UI is turned on, with an in-memory database that
// certificates can be recorded in directly
const setup = async (): Promise<{ ca: SshCa, env: SshCaBindings, seed: (...seeds: Seed[]) => string[] }> => {
	const sqlite = new DatabaseSync(":memory:")
	const env = makeEnv({
		DB: fromNodeSqlite(sqlite),
		PRIVATE_KEY: new MockSecretStore(ecdsaKey.ca().privateKey),
		ADMIN_JWT_HEADER: Header,
		ADMIN_JWKS_URL: proxy.jwksUrl,
		ADMIN_JWT_ISSUER: proxy.issuer,
		ADMIN_JWT_AUD: proxy.audience,
		ADMIN_ALLOWED_EMAILS: AdminEmail,
	})
	await migrateOnce(env.DB, migrations)

	let next = 1
	const insert = sqlite.prepare(`INSERT INTO certificates
		(serial, key_id, principals, extensions, valid_after, valid_before, revoked_at, certificate_type, public_key, requested_by, revoked_by, revocation_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)

	// records certificates in order, so later ones are newer, and returns their serials
	const seed = (...seeds: Seed[]): string[] => seeds.map((s) => {
		const serial = s.serial ?? `${1000 + next++}`
		const now = Date.now()
		insert.run(
			serial,
			s.keyId ?? "user@example.com",
			s.principals ?? (s.type === CertificateType.Host ? "CN=host.example.com" : "UID=user"),
			s.extensions === undefined ? "permit-pty" : s.extensions,
			new Date(now - 2 * HourMs).toISOString(),
			new Date(now + (s.expiresIn ?? 24) * HourMs).toISOString(),
			s.revoked === undefined ? null : new Date(now - HourMs).toISOString(),
			s.type ?? CertificateType.User,
			s.publicKey === undefined ? ecdsaKey.user().publicKey : s.publicKey,
			s.requestedBy === undefined ? "user@example.com" : s.requestedBy,
			s.revoked?.by ?? null,
			s.revoked?.reason ?? null,
		)
		return serial
	})

	return { ca: createSshCa(env), env, seed }
}

const get = async (ca: SshCa, path: string): Promise<Response> => await ca.fetch(new Request(`${Origin}${path}`, {
	headers: { [Header]: await proxy.sign({ email: AdminEmail }) },
}))

// the serials linked from a list page, in the order they are shown
const listedSerials = (body: string): string[] => [...body.matchAll(/<a href="\/admin\/(?:user|host)\/certificates\/(\d+)">/g)].map((m) => m[1] ?? "")

// the link to the next page of a list page, if it has one
const nextPage = (body: string): string | undefined => /<a href="([^"]+)" rel="next">/.exec(body)?.[1]?.replaceAll("&amp;", "&")

const list = async (ca: SshCa, path: string): Promise<{ response: Response, body: string, serials: string[] }> => {
	const response = await get(ca, path)
	const body = await response.text()
	return { response, body, serials: listedSerials(body) }
}

describe("certificate list", () => {
	it("should show only valid user certificates, newest first, by default", async () => {
		const { ca, seed } = await setup()
		const [older, expired, revoked, host, newer] = seed(
			{},
			{ expiresIn: -1 },
			{ revoked: { by: "key-holder", reason: null } },
			{ type: CertificateType.Host },
			{},
		)

		const { response, serials } = await list(ca, "/admin/user/certificates")

		expect(response.status).toBe(200)
		expect(serials).toEqual([newer, older])
		expect(serials).not.toContain(expired)
		expect(serials).not.toContain(revoked)
		expect(serials).not.toContain(host)
	})

	it.each([
		["valid", ["valid"]],
		["expired", ["expired"]],
		["revoked", ["revoked and expired", "revoked"]],
		["all", ["revoked and expired", "revoked", "expired", "valid"]],
	])("should show %s certificates for that status", async (status, expected) => {
		const { ca, seed } = await setup()
		const [valid, expired, revoked, both] = seed(
			{ keyId: "valid" },
			{ keyId: "expired", expiresIn: -1 },
			{ keyId: "revoked", revoked: { by: AdminEmail, reason: "lost" } },
			{ keyId: "revoked and expired", expiresIn: -1, revoked: { by: "key-holder", reason: null } },
		)
		const serials = { valid, expired, revoked, "revoked and expired": both }

		const page = await list(ca, `/admin/user/certificates?status=${status}`)

		expect(page.response.status).toBe(200)
		expect(page.serials).toEqual(expected.map((name) => serials[name as keyof typeof serials]))
	})

	it("should show a certificate that is revoked and expired as revoked", async () => {
		const { ca, seed } = await setup()
		seed({ expiresIn: -1, revoked: { by: "key-holder", reason: null } })

		const { body } = await list(ca, "/admin/user/certificates?status=all")
		expect(body).toContain("<td>revoked</td>")
		expect(body).not.toContain("<td>expired</td>")
	})

	it("should match a principal exactly", async () => {
		const { ca, seed } = await setup()
		const [root, , both, ROOT] = seed(
			{ principals: "UID=root" },
			{ principals: "UID=rootless" },
			{ principals: "UID=alice,UID=root,UID=bob" },
			{ principals: "UID=ROOT" },
			{ principals: "UID=xroot" },
		)

		expect((await list(ca, "/admin/user/certificates?principal=root")).serials).toEqual([both, root])
		expect((await list(ca, "/admin/user/certificates?principal=ROOT")).serials).toEqual([ROOT])
		expect((await list(ca, "/admin/user/certificates?principal=roo")).serials).toEqual([])
	})

	it("should match host principals", async () => {
		const { ca, seed } = await setup()
		const [host] = seed(
			{ type: CertificateType.Host, principals: "CN=host.example.com,CN=host" },
			{ type: CertificateType.Host, principals: "CN=other.example.com" },
		)

		expect((await list(ca, "/admin/host/certificates?principal=host")).serials).toEqual([host])
	})

	it("should treat LIKE patterns in a principal literally", async () => {
		const { ca, seed } = await setup()
		seed({ principals: "UID=alice" })

		expect((await list(ca, "/admin/user/certificates?principal=%25")).serials).toEqual([])
		expect((await list(ca, "/admin/user/certificates?principal=_lice")).serials).toEqual([])
	})

	it("should match part of a key ID, case-insensitively", async () => {
		const { ca, seed } = await setup()
		const [alice, , upper] = seed(
			{ keyId: "alice@example.com" },
			{ keyId: "bob@example.com" },
			{ keyId: "ALICE@EXAMPLE.ORG" },
		)

		expect((await list(ca, "/admin/user/certificates?key_id=Alice")).serials).toEqual([upper, alice])
	})

	it("should match % and _ in a key ID literally", async () => {
		const { ca, seed } = await setup()
		const [percent, underscore, backslash] = seed(
			{ keyId: "100%@example.com" },
			{ keyId: "host_web" },
			{ keyId: "back\\slash" },
			{ keyId: "hostXweb" },
			{ keyId: "1000@example.com" },
		)

		expect((await list(ca, "/admin/user/certificates?key_id=%25")).serials).toEqual([percent])
		expect((await list(ca, "/admin/user/certificates?key_id=t_w")).serials).toEqual([underscore])
		expect((await list(ca, "/admin/user/certificates?key_id=%5C")).serials).toEqual([backslash])
	})

	it("should match a serial exactly", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({ serial: "123" }, { serial: "1234" }, { serial: "4123" })

		expect((await list(ca, "/admin/user/certificates?serial=123")).serials).toEqual([serial])
		expect((await list(ca, "/admin/user/certificates?serial=0123")).serials).toEqual([serial])
		expect((await list(ca, "/admin/user/certificates?serial=12")).serials).toEqual([])
	})

	it("should combine filters", async () => {
		const { ca, seed } = await setup()
		const [match] = seed(
			{ keyId: "alice@example.com", principals: "UID=alice", expiresIn: -1 },
			{ keyId: "alice@example.com", principals: "UID=alice" },
			{ keyId: "bob@example.com", principals: "UID=alice", expiresIn: -1 },
		)

		expect((await list(ca, "/admin/user/certificates?status=expired&principal=alice&key_id=alice")).serials).toEqual([match])
	})

	it("should ignore empty filters, as the filter form submits them", async () => {
		const { ca, seed } = await setup()
		const serials = seed({}, {})

		const page = await list(ca, "/admin/user/certificates?status=&principal=&key_id=&serial=")
		expect(page.response.status).toBe(200)
		expect(page.serials).toEqual(serials.reverse())
	})

	it("should only show certificates of the tab's type", async () => {
		const { ca, seed } = await setup()
		const [user, host] = seed({ type: CertificateType.User }, { type: CertificateType.Host })

		expect((await list(ca, "/admin/user/certificates")).serials).toEqual([user])
		expect((await list(ca, "/admin/host/certificates")).serials).toEqual([host])
	})

	it("should link both tabs, marking the current one", async () => {
		const { ca } = await setup()

		const { body } = await list(ca, "/admin/host/certificates")
		expect(body).toContain(`<a href="/admin/user/certificates">User certificates</a>`)
		expect(body).toContain(`<a href="/admin/host/certificates" aria-current="page">Host certificates</a>`)
	})

	it("should keep the filters in the form", async () => {
		const { ca } = await setup()

		const { body } = await list(ca, "/admin/user/certificates?status=expired&principal=alice&key_id=example&serial=42")
		expect(body).toContain(`<form class="filters" method="get" action="/admin/user/certificates">`)
		expect(body).toContain(`<option value="expired" selected="">Expired</option>`)
		expect(body).toContain(`name="principal" value="alice"`)
		expect(body).toContain(`name="key_id" value="example"`)
		expect(body).toContain(`name="serial" inputmode="numeric" value="42"`)
	})

	it("should page 50 at a time, visiting every certificate once and keeping the filters", async () => {
		const { ca, seed } = await setup()
		const matching = seed(...Array.from({ length: 120 }, (_, i): Seed => ({ keyId: i % 2 === 0 ? `match-${i}@example.com` : `other-${i}@example.com` })))
			.filter((_, i) => i % 2 === 0)
		seed(...Array.from({ length: 60 }, (): Seed => ({ keyId: "match@example.com", expiresIn: -1 })))

		const visited: string[] = []
		const pageSizes: number[] = []
		let path: string | undefined = "/admin/user/certificates?key_id=match"
		while (path !== undefined) {
			const page = await list(ca, path)
			expect(page.response.status).toBe(200)
			visited.push(...page.serials)
			pageSizes.push(page.serials.length)
			path = nextPage(page.body)
			if (path !== undefined) {
				const params = new URL(path, Origin).searchParams
				expect(params.get("status")).toBe("valid")
				expect(params.get("key_id")).toBe("match")
				expect(params.get("before")).toMatch(/^\d+$/)
			}
		}

		expect(visited).toEqual([...matching].reverse())
		expect(pageSizes).toEqual([50, 10])
	})

	it("should not link a next page when the last page is exactly full", async () => {
		const { ca, seed } = await setup()
		seed(...Array.from({ length: 50 }, (): Seed => ({})))

		const page = await list(ca, "/admin/user/certificates")
		expect(page.serials).toHaveLength(50)
		expect(nextPage(page.body)).toBeUndefined()
	})

	it("should not skip or repeat certificates recorded while paging", async () => {
		const { ca, env, seed } = await setup()
		const first = seed(...Array.from({ length: 51 }, (): Seed => ({})))

		const page1 = await list(ca, "/admin/user/certificates")
		seed({}, {})
		const next = nextPage(page1.body)
		expect(next).toBeDefined()
		const page2 = await list(ca, next ?? "")

		expect([...page1.serials, ...page2.serials]).toEqual([...first].reverse())
		// the database query agrees with what is shown
		expect((await listCertificates(env, { certificateType: CertificateType.User, status: "valid" })).certificates).toHaveLength(50)
	})

	it.each([
		["an unknown status", "status=current"],
		["a serial that is not a number", "serial=abc"],
		["a negative serial", "serial=-1"],
		["a serial that is too large", "serial=18446744073709551616"],
		["a cursor that is not a number", "before=abc"],
		["a cursor of zero", "before=0"],
		["a principal with a comma", "principal=alice%2Cbob"],
		["a key ID that is too long", `key_id=${"a".repeat(257)}`],
	])("should refuse %s with a 400 page", async (_name, query) => {
		const { ca } = await setup()

		const response = await get(ca, `/admin/user/certificates?${query}`)
		expect(response.status).toBe(400)
		expect(response.headers.get("Content-Type")).toMatch(/^text\/html/)
		expect(await response.text()).toContain("Invalid filters")
		for (const [name, value] of Object.entries(AdminSecurityHeaders)) {
			expect(response.headers.get(name), name).toBe(value)
		}
	})

	it("should accept the largest serial", () => {
		expect(CertificateListQuery.parse({ serial: "18446744073709551615" }).serial).toBe(18446744073709551615n)
	})

	it("should answer an unknown certificate kind with 404", async () => {
		const { ca } = await setup()
		expect((await get(ca, "/admin/other/certificates")).status).toBe(404)
	})

	it("should escape values", async () => {
		const { ca, seed } = await setup()
		seed({ keyId: "<script>alert(1)</script>", principals: "UID=<b>bold</b>" })

		const { body } = await list(ca, "/admin/user/certificates?key_id=%3Cscript%3E")
		expect(body).not.toContain("<script>")
		expect(body).not.toContain("<b>")
		expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;")
		expect(body).toContain("&lt;b&gt;bold&lt;/b&gt;")
		expect(body).toContain(`name="key_id" value="&lt;script&gt;"`)
	})

	it("should require an admin", async () => {
		const { ca } = await setup()

		const response = await ca.fetch(new Request(`${Origin}/admin/user/certificates`))
		expect(response.status).toBe(401)
	})
})

describe("certificate detail", () => {
	it("should show every field of a valid certificate", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({
			keyId: "alice@example.com",
			principals: "UID=alice,UID=admins",
			extensions: "permit-pty,permit-agent-forwarding",
			requestedBy: "alice@example.com",
		})

		const response = await get(ca, `/admin/user/certificates/${serial}`)
		expect(response.status).toBe(200)
		const body = await response.text()

		expect(body).toContain(`<dt>Serial</dt><dd>${serial}</dd>`)
		expect(body).toContain("<dt>Certificate type</dt><dd>user</dd>")
		expect(body).toContain("<dt>Key ID</dt><dd>alice@example.com</dd>")
		expect(body).toContain(`<dt>Principals</dt><dd><ul class="plain"><li>alice</li><li>admins</li></ul></dd>`)
		expect(body).toContain(`<dt>Extensions</dt><dd><ul class="plain"><li>permit-pty</li><li>permit-agent-forwarding</li></ul></dd>`)
		expect(body).toMatch(/<dt>Valid from<\/dt><dd>\d{4}-\d{2}-\d{2}T[\d:.]+Z<\/dd>/)
		expect(body).toMatch(/<dt>Valid until<\/dt><dd>\d{4}-\d{2}-\d{2}T[\d:.]+Z<\/dd>/)
		expect(body).toContain("<dt>Status</dt><dd>valid</dd>")
		expect(body).toContain(`<dt>Public key fingerprint</dt><dd><code>${PublicKey.parse(ecdsaKey.user().publicKey).fingerprint()}</code></dd>`)
		expect(body).toContain("<dt>Requested by</dt><dd>alice@example.com</dd>")
		// the revocation fields are only shown for a revoked certificate
		expect(body).not.toContain("Revoked at")
		expect(body).not.toContain("Revoked by")
		expect(body).not.toContain("Revocation reason")
	})

	it("should show host principals without their prefix", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({ type: CertificateType.Host, principals: "CN=host.example.com,CN=host" })

		const body = await (await get(ca, `/admin/host/certificates/${serial}`)).text()
		expect(body).toContain(`<dt>Principals</dt><dd><ul class="plain"><li>host.example.com</li><li>host</li></ul></dd>`)
		expect(body).toContain("<dt>Certificate type</dt><dd>host</dd>")
	})

	it("should show the revocation of a revoked certificate", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({ revoked: { by: AdminEmail, reason: "key was lost" } })

		const body = await (await get(ca, `/admin/user/certificates/${serial}`)).text()
		expect(body).toContain("<dt>Status</dt><dd>revoked</dd>")
		expect(body).toMatch(/<dt>Revoked at<\/dt><dd>\d{4}-\d{2}-\d{2}T[\d:.]+Z<\/dd>/)
		expect(body).toContain(`<dt>Revoked by</dt><dd>${AdminEmail}</dd>`)
		expect(body).toContain("<dt>Revocation reason</dt><dd>key was lost</dd>")
	})

	it("should show unknown for audit values that were not recorded", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({ requestedBy: null, publicKey: null, extensions: null, revoked: { by: null, reason: null } })

		const body = await (await get(ca, `/admin/user/certificates/${serial}`)).text()
		expect(body).toContain("<dt>Requested by</dt><dd>unknown</dd>")
		expect(body).toContain("<dt>Revoked by</dt><dd>unknown</dd>")
		expect(body).toContain("<dt>Revocation reason</dt><dd>unknown</dd>")
		expect(body).toContain("<dt>Public key fingerprint</dt><dd><code>unknown</code></dd>")
		expect(body).toContain("<dt>Extensions</dt><dd>none</dd>")
	})

	it("should show an expired certificate as expired", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({ expiresIn: -1 })

		const body = await (await get(ca, `/admin/user/certificates/${serial}`)).text()
		expect(body).toContain("<dt>Status</dt><dd>expired</dd>")
	})

	it.each([
		["an unknown serial", "/admin/user/certificates/999999"],
		["a serial that is not a number", "/admin/user/certificates/abc"],
		["a serial of the other certificate type", "/admin/host/certificates/{serial}"],
	])("should answer %s with a 404 page", async (_name, path) => {
		const { ca, seed } = await setup()
		const [serial] = seed({ type: CertificateType.User })

		const response = await get(ca, path.replace("{serial}", serial ?? ""))
		expect(response.status).toBe(404)
		expect(await response.text()).toContain("Certificate not found")
		for (const [name, value] of Object.entries(AdminSecurityHeaders)) {
			expect(response.headers.get(name), name).toBe(value)
		}
	})

	it("should escape values", async () => {
		const { ca, seed } = await setup()
		const [serial] = seed({
			keyId: "<script>alert(1)</script>",
			principals: "UID=<b>bold</b>",
			extensions: "<i>ext</i>",
			requestedBy: "<u>x</u>@example.com",
			revoked: { by: "<em>admin</em>", reason: "<img src=x onerror=alert(1)>" },
		})

		const body = await (await get(ca, `/admin/user/certificates/${serial}`)).text()
		for (const tag of ["<script>", "<b>", "<i>", "<u>", "<em>", "<img"]) {
			expect(body).not.toContain(tag)
		}
		expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;")
		expect(body).toContain("&lt;img src=x onerror=alert(1)&gt;")
	})
})
