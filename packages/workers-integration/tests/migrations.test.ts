import { env, exports } from "cloudflare:workers"
// @ts-ignore: this import errors but is fine in tests
import { adminSecretsStore } from "cloudflare:test"
import { describe, it, expect } from "vitest"
import { privateKeyString } from "./keys/ecdsa"
// the backfill is not part of the package's exports, but its SQL must be run
// on D1 to know that D1 accepts it
import { migration as renewalOf } from "../../core/src/db/migrations/0005_renewal_of"

const admin = adminSecretsStore(env.PRIVATE_KEY)
await admin.create(privateKeyString)

describe("database migrations", () => {
	it("are applied once when concurrent requests use a fresh database", async () => {
		const responses = await Promise.all(Array.from({ length: 10 }, () => exports.default.fetch("http://example.com/api/v4/user/krl")))

		expect(responses.map(r => r.status)).toEqual(Array.from({ length: 10 }, () => 200))

		const { results } = await env.DB.prepare("SELECT name FROM migrations").all()
		expect(results).toEqual([{ name: "0001_initial_schema" }, { name: "0002_krl_version" }, { name: "0003_krl_revision" }, { name: "0004_certificate_audit" }, { name: "0005_renewal_of" }, { name: "0006_client_address" }])
	})

	it("link renewals recorded before 0005_renewal_of on D1", async () => {
		expect((await exports.default.fetch("http://example.com/api/v4/user/krl")).status).toBe(200)

		const insert = env.DB.prepare(`INSERT INTO certificates (serial, key_id, principals, extensions, valid_after, valid_before, revoked_at, certificate_type, public_key, requested_by, revoked_by, revocation_reason)
			VALUES (?, 'host', 'CN=host.example.com', '', ?, '2026-12-31T00:00:00.000Z', ?, 1, 'ssh-ed25519 AAAA', 'user@example.com', ?, ?)`)
		await env.DB.batch([
			insert.bind("9001", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.250Z", "key-holder", "renewal"),
			insert.bind("9002", "2026-01-02T00:00:00.000Z", "2026-01-03T00:00:01.500Z", "key-holder", "renewal"),
			insert.bind("9003", "2026-01-03T00:00:01.000Z", null, null, null),
		])

		// the column and its index already exist, so only the backfill is run
		// again: the temporary index, the match (with AS MATERIALIZED and
		// UPDATE ... FROM, which D1 must support), dropping the index, and
		// clearing the requesters of renewals
		const backfill = renewalOf.statements.filter((sql) => !/^ALTER\b/.test(sql) && !sql.includes("idx_certificates_renewal_of"))
		expect(backfill.some((sql) => sql.includes("MATERIALIZED"))).toBe(true)
		await env.DB.batch(backfill.map((sql) => env.DB.prepare(sql)))

		const { results } = await env.DB.prepare("SELECT serial, requested_by, renewal_of FROM certificates WHERE serial IN ('9001', '9002', '9003') ORDER BY serial").all()
		expect(results).toEqual([
			{ serial: "9001", requested_by: "user@example.com", renewal_of: null },
			{ serial: "9002", requested_by: null, renewal_of: "9001" },
			{ serial: "9003", requested_by: null, renewal_of: "9002" },
		])

		// the index made for the match is dropped again
		const indexes = await env.DB.prepare("SELECT name FROM sqlite_master WHERE name = 'tmp_0005_renewal_candidates'").all()
		expect(indexes.results).toEqual([])
	})
})
