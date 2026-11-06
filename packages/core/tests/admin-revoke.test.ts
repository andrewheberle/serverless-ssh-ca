import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { z } from "zod"
import { cloudflareClientIp, createSshCa, type CaDatabase, type CaRateLimiter, type SshCa, type SshCaBindings } from "../src/index.js"
import { AdminSecurityHeaders } from "../src/admin/index.js"
import { getKrlRevision, recordCertificate, revokeCertificate, type RevocationResult } from "../src/db/index.js"
import { CertificateType } from "../src/db/types.js"
import { fromNodeSqlite } from "../src/node/index.js"
import type { SshCertificate } from "../src/ssh/certificate.js"
import { makeEnv } from "./env.js"
import { hostCertificate } from "./helpers/certificate.js"
import { generateRequestProof } from "./helpers/proof.js"
import { createProxy, type Proxy } from "./helpers/proxy.js"
import { MockSecretStore } from "./helpers/secret.js"
import { isRevoked } from "./helpers/ssh-keygen.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

const Header = "Cf-Access-Jwt-Assertion"
// the email as the proxy gives it, which is recorded exactly, although it is
// compared with the allowlist case-insensitively
const AdminEmail = "Admin@Example.com"
const Origin = "https://ssh-ca.example.com"

let proxy: Proxy

beforeAll(async () => {
	proxy = await createProxy("admin-revoke-tests")
})

beforeEach(() => {
	proxy.serveJwks()
})

afterEach(() => {
	vi.restoreAllMocks()
})

const KrlResponse = z.object({ krl: z.string() })

type Recorded = { serial: string, revoked_at: string | null, revoked_by: string | null, revocation_reason: string | null }

// a CA whose admin UI is turned on, with a recorded host certificate
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
	const certificate = hostCertificate(ecdsaKey.ca(), ecdsaKey.host())
	await recordCertificate(env, certificate, certificate.keyId, CertificateType.Host, "requester@example.com")

	const recorded = (): Recorded | undefined => sqlite.prepare("SELECT serial, revoked_at, revoked_by, revocation_reason FROM certificates WHERE serial = ?")
		.get(`${certificate.serial}`) as Recorded | undefined
	const expire = (): void => {
		sqlite.prepare("UPDATE certificates SET valid_before = ? WHERE serial = ?").run(new Date(Date.now() - 60_000).toISOString(), `${certificate.serial}`)
	}
	const ca = createSshCa(env, overrides.RATE_LIMITER === undefined ? {} : { rateLimitKey: cloudflareClientIp })

	return { ca, env, sqlite, certificate, recorded, expire }
}

const detailPath = (certificate: SshCertificate, kind = "host"): string => `/admin/${kind}/certificates/${certificate.serial}`

// a POST of the revoke form that passes the checks against cross-site requests
const revoke = async (ca: SshCa, certificate: SshCertificate, form: Record<string, string> = { reason: "Key was lost", confirm: "yes" }, options: { headers?: Record<string, string>, kind?: string, email?: string } = {}): Promise<Response> => {
	return await ca.fetch(new Request(`${Origin}${detailPath(certificate, options.kind)}/revoke`, {
		method: "POST",
		headers: {
			[Header]: await proxy.sign({ email: options.email ?? AdminEmail }),
			"Origin": Origin,
			"Sec-Fetch-Site": "same-origin",
			"Content-Type": "application/x-www-form-urlencoded",
			...options.headers,
		},
		body: new URLSearchParams(form).toString(),
	}))
}

const get = async (ca: SshCa, path: string): Promise<Response> => await ca.fetch(new Request(`${Origin}${path}`, {
	headers: { [Header]: await proxy.sign({ email: AdminEmail }) },
}))

const krl = async (ca: SshCa, type: "user" | "host"): Promise<Buffer> => {
	const response = await ca.fetch(new Request(`${Origin}/api/v4/${type}/krl`))
	expect(response.status).toBe(200)
	return Buffer.from(KrlResponse.parse(await response.json()).krl, "base64")
}

describe("admin revocation", () => {
	it("should revoke a certificate, record who revoked it and why, and redirect to it", async () => {
		const { ca, env, certificate, recorded } = await setup()
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)

		const response = await revoke(ca, certificate, { reason: "  Key was lost \n", confirm: "yes" })

		expect(response.status).toBe(303)
		expect(response.headers.get("Location")).toBe(detailPath(certificate))
		expect(recorded()).toMatchObject({ revoked_by: AdminEmail, revocation_reason: "Key was lost" })
		expect(recorded()?.revoked_at).not.toBeNull()
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
		expect(isRevoked(await krl(ca, "host"), certificate.toString())).toBe(true)
	})

	it("should show the revocation on the detail page, without the form", async () => {
		const { ca, certificate } = await setup()
		await revoke(ca, certificate)

		const body = await (await get(ca, detailPath(certificate))).text()
		expect(body).toContain(`<dt>Revoked by</dt><dd>${AdminEmail}</dd>`)
		expect(body).toContain("<dt>Revocation reason</dt><dd>Key was lost</dd>")
		expect(body).not.toContain("<form class=\"revoke\"")
	})

	it("should revoke user certificates into the user KRL", async () => {
		const { ca, env, certificate } = await setup()
		// a certificate recorded as a user certificate, as the KRL only needs its serial
		const user = hostCertificate(ecdsaKey.ca(), ecdsaKey.user(), { principals: ["alice"] })
		await recordCertificate(env, user, "alice@example.com", CertificateType.User)

		expect((await revoke(ca, user, undefined, { kind: "user" })).status).toBe(303)

		expect(isRevoked(await krl(ca, "user"), user.toString())).toBe(true)
		expect(isRevoked(await krl(ca, "host"), certificate.toString())).toBe(false)
		expect(await getKrlRevision(env, CertificateType.User)).toBe(1n)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)
	})

	it("should write the audit log line", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const { ca, certificate } = await setup({ LOG_LEVEL: "info" })

		await revoke(ca, certificate)

		expect(log).toHaveBeenCalledWith(expect.objectContaining({
			level: "info",
			message: "certificate revoked",
			serial: `${certificate.serial}`,
			certificate_type: "host",
			revoked_by: AdminEmail,
			revocation_reason: "Key was lost",
		}))
	})

	it("should show a revoke form only for a valid certificate", async () => {
		const valid = await setup()
		expect(await (await get(valid.ca, detailPath(valid.certificate))).text()).toContain(`<form class="revoke" method="post" action="${detailPath(valid.certificate)}/revoke">`)

		const expired = await setup()
		expired.expire()
		expect(await (await get(expired.ca, detailPath(expired.certificate))).text()).not.toContain("<form class=\"revoke\"")
	})

	it("should refuse an expired certificate with 422 and change nothing", async () => {
		const { ca, env, certificate, recorded, expire } = await setup()
		expire()

		const response = await revoke(ca, certificate)

		expect(response.status).toBe(422)
		expect(await response.text()).toContain("Certificate has expired")
		expect(recorded()).toMatchObject({ revoked_at: null, revoked_by: null, revocation_reason: null })
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)
	})

	it("should refuse a certificate that is already revoked with 409 and change nothing", async () => {
		const { ca, env, certificate, recorded } = await setup()
		await revokeCertificate(env, { serial: certificate.serial, certificateType: CertificateType.Host, revoker: { kind: "keyHolder", publicKey: certificate.publicKey } })
		const before = recorded()

		const response = await revoke(ca, certificate)

		expect(response.status).toBe(409)
		expect(await response.text()).toContain("Certificate already revoked")
		expect(recorded()).toEqual(before)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
	})

	it.each([
		["an unknown serial", "/admin/host/certificates/999999/revoke"],
		["a serial that is not a number", "/admin/host/certificates/abc/revoke"],
		["the other certificate type", "/admin/user/certificates/{serial}/revoke"],
	])("should answer %s with a 404 page", async (_name, path) => {
		const { ca, certificate, recorded } = await setup()

		const response = await ca.fetch(new Request(`${Origin}${path.replace("{serial}", `${certificate.serial}`)}`, {
			method: "POST",
			headers: { [Header]: await proxy.sign({ email: AdminEmail }), "Origin": Origin, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded" },
			body: "reason=lost&confirm=yes",
		}))

		expect(response.status).toBe(404)
		expect(recorded()?.revoked_at).toBeNull()
	})

	it.each([
		["no reason", { confirm: "yes" }, "Give a reason for revoking the certificate."],
		["an empty reason", { reason: "", confirm: "yes" }, "Give a reason for revoking the certificate."],
		["a reason of only whitespace", { reason: " \n\t ", confirm: "yes" }, "Give a reason for revoking the certificate."],
		["a reason over 500 characters", { reason: "a".repeat(501), confirm: "yes" }, "The reason must be at most 500 characters."],
		["an unticked confirmation", { reason: "Key was lost" }, "Tick the box to confirm that the revocation cannot be undone."],
		["a confirmation of another value", { reason: "Key was lost", confirm: "on" }, "Tick the box to confirm that the revocation cannot be undone."],
	])("should show the form again with a 422 for %s, and revoke nothing", async (_name, form, error) => {
		const { ca, env, certificate, recorded } = await setup()

		const response = await revoke(ca, certificate, form)

		expect(response.status).toBe(422)
		const body = await response.text()
		expect(body).toContain(`<form class="revoke"`)
		expect(body).toContain(`<li>${error}</li>`)
		expect(recorded()?.revoked_at).toBeNull()
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)
	})

	it("should accept a reason of exactly 500 characters once trimmed", async () => {
		const { ca, certificate, recorded } = await setup()

		expect((await revoke(ca, certificate, { reason: ` ${"a".repeat(500)} `, confirm: "yes" })).status).toBe(303)
		expect(recorded()?.revocation_reason).toBe("a".repeat(500))
	})

	it("should keep the reason entered when the form is shown again, escaped", async () => {
		const { ca, certificate } = await setup()

		const body = await (await revoke(ca, certificate, { reason: "</textarea><script>alert(1)</script>" })).text()
		expect(body).not.toContain("<script>")
		expect(body).toContain("&lt;/textarea&gt;&lt;script&gt;alert(1)&lt;/script&gt;</textarea>")
	})

	it("should escape the reason on the detail page", async () => {
		const { ca, certificate } = await setup()
		await revoke(ca, certificate, { reason: "<img src=x onerror=alert(1)>", confirm: "yes" })

		const body = await (await get(ca, detailPath(certificate))).text()
		expect(body).not.toContain("<img")
		expect(body).toContain("&lt;img src=x onerror=alert(1)&gt;")
	})

	it("should refuse a request body over 16 KiB", async () => {
		const { ca, certificate, recorded } = await setup()

		const response = await revoke(ca, certificate, { reason: "a".repeat(20 * 1024), confirm: "yes" })
		expect(response.status).toBe(413)
		expect(recorded()?.revoked_at).toBeNull()
	})

	it.each([
		["another Origin", { "Origin": "https://evil.example.com" }],
		["no Origin", { "Origin": "" }],
		["no Sec-Fetch-Site", { "Sec-Fetch-Site": "" }],
		["a cross-site Sec-Fetch-Site", { "Sec-Fetch-Site": "cross-site" }],
		["a same-site Sec-Fetch-Site", { "Sec-Fetch-Site": "same-site" }],
	])("should refuse a revocation with %s and revoke nothing", async (_name, headers) => {
		const { ca, certificate, recorded } = await setup()
		const sent = {
			[Header]: await proxy.sign({ email: AdminEmail }),
			"Origin": Origin,
			"Sec-Fetch-Site": "same-origin",
			"Content-Type": "application/x-www-form-urlencoded",
			...headers,
		}

		// an empty value leaves the header out
		const response = await ca.fetch(new Request(`${Origin}${detailPath(certificate)}/revoke`, {
			method: "POST",
			headers: Object.fromEntries(Object.entries(sent).filter(([, value]) => value !== "")),
			body: "reason=Key+was+lost&confirm=yes",
		}))

		expect(response.status).toBe(403)
		for (const [name, value] of Object.entries(AdminSecurityHeaders)) {
			expect(response.headers.get(name), name).toBe(value)
		}
		expect(recorded()?.revoked_at).toBeNull()
	})

	it("should use a referrer policy under which browsers send the Origin of the admin UI's own forms", async () => {
		const { ca, certificate } = await setup()

		// with no-referrer, browsers send "Origin: null" on a form post, which
		// the check against cross-site requests refuses, so no admin could
		// revoke anything. same-origin still sends other sites no referrer
		const response = await get(ca, detailPath(certificate))
		expect(response.headers.get("Referrer-Policy")).toBe("same-origin")
	})

	it("should refuse a revocation with an Origin of null, as sent by a page with no referrer", async () => {
		const { ca, certificate, recorded } = await setup()

		expect((await revoke(ca, certificate, undefined, { headers: { "Origin": "null" } })).status).toBe(403)
		expect(recorded()?.revoked_at).toBeNull()
	})

	it("should refuse someone who is not an admin, and revoke nothing", async () => {
		const { ca, certificate, recorded } = await setup()

		expect((await revoke(ca, certificate, undefined, { email: "someone@example.com" })).status).toBe(403)
		expect(recorded()?.revoked_at).toBeNull()
	})

	it("should rate limit revocations by the admin's email", async () => {
		const keys: string[] = []
		const limiter: CaRateLimiter = { limit: async ({ key }) => { keys.push(key); return { success: false } } }
		const { ca, certificate, recorded } = await setup({ RATE_LIMITER: limiter })

		const response = await revoke(ca, certificate)

		expect(response.status).toBe(429)
		expect(keys).toEqual([`admin:${AdminEmail}`])
		expect(recorded()?.revoked_at).toBeNull()
	})
})

// a database whose batches wait until a number of them have been started, so
// every revocation reads the certificate before any of them revokes it
const withBatchBarrier = (db: CaDatabase, count: number): CaDatabase => {
	let waiting = 0
	let release: () => void = () => undefined
	const barrier = new Promise<void>((resolve) => { release = resolve })

	return {
		prepare: (query) => db.prepare(query),
		exec: async (query) => await db.exec(query),
		batch: async (statements) => {
			waiting++
			if (waiting === count) {
				release()
			}
			await barrier

			return await db.batch(statements)
		},
	}
}

describe("admin revocation operation", () => {
	it("should revoke a certificate once when admins revoke it concurrently", async () => {
		const requests = 5
		const { env, certificate, recorded } = await setup()
		const racing = { ...env, DB: withBatchBarrier(env.DB, requests) }

		const results = await Promise.all(Array.from({ length: requests }, async (_, i): Promise<RevocationResult> => await revokeCertificate(racing, {
			serial: certificate.serial,
			certificateType: CertificateType.Host,
			revoker: { kind: "admin", email: `admin${i}@example.com`, reason: `reason ${i}` },
		})))

		const revoked = results.filter((result) => result.kind === "revoked")
		expect(revoked).toHaveLength(1)
		expect(results.filter((result) => result.kind === "alreadyRevoked")).toHaveLength(requests - 1)
		expect(recorded()?.revoked_at).toBe(revoked[0]?.revokedAt)
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(1n)
	})

	it("should not revoke a certificate that expires after it is read", async () => {
		const { env, sqlite, certificate, recorded } = await setup()
		// expire the certificate between the operation reading it and revoking it
		const expiring: CaDatabase = {
			prepare: (query) => env.DB.prepare(query),
			exec: async (query) => await env.DB.exec(query),
			batch: async (statements) => {
				sqlite.prepare("UPDATE certificates SET valid_before = ? WHERE serial = ?").run(new Date(Date.now() - 1000).toISOString(), `${certificate.serial}`)
				return await env.DB.batch(statements)
			},
		}

		const result = await revokeCertificate({ ...env, DB: expiring }, {
			serial: certificate.serial,
			certificateType: CertificateType.Host,
			revoker: { kind: "admin", email: AdminEmail, reason: "lost" },
		})

		expect(result).toEqual({ kind: "expired" })
		expect(recorded()?.revoked_at).toBeNull()
		expect(await getKrlRevision(env, CertificateType.Host)).toBe(0n)
	})

	it("should let an admin revoke a certificate whose public key was not recorded", async () => {
		const { env, sqlite, certificate, recorded } = await setup()
		sqlite.prepare("UPDATE certificates SET public_key = NULL WHERE serial = ?").run(`${certificate.serial}`)

		const result = await revokeCertificate(env, { serial: certificate.serial, certificateType: CertificateType.Host, revoker: { kind: "admin", email: AdminEmail, reason: "lost" } })

		expect(result.kind).toBe("revoked")
		expect(recorded()?.revoked_by).toBe(AdminEmail)
	})

	it("should still let a key holder revoke an expired certificate", async () => {
		const { env, certificate, expire } = await setup()
		expire()

		const result = await revokeCertificate(env, { serial: certificate.serial, certificateType: CertificateType.Host, revoker: { kind: "keyHolder", publicKey: certificate.publicKey } })
		expect(result.kind).toBe("revoked")
	})

	it("should still let a key holder revoke an expired certificate through the v4 API, with the same response", async () => {
		const { ca, certificate, recorded, expire } = await setup()
		expire()
		const path = `/api/v4/host/certificates/${certificate.serial}`

		const response = await ca.fetch(new Request(`${Origin}${path}`, {
			method: "DELETE",
			headers: { "Proof-Of-Possession": generateRequestProof(ecdsaKey.host(), "DELETE", path) },
		}))

		expect(response.status).toBe(200)
		expect(await response.json()).toEqual({ revoked_at: recorded()?.revoked_at })
		expect(recorded()).toMatchObject({ revoked_by: "key-holder", revocation_reason: null })
	})
})
