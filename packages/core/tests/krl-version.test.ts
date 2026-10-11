import { describe, it, expect } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { CertificateType, getKrlVersion } from "../src/db/index.js"
import { fromNodeSqlite } from "../src/node/sqlite.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"

const fresh = (): { raw: DatabaseSync, env: SshCaBindings } => {
	const raw = new DatabaseSync(":memory:")
	return { raw, env: makeEnv({ DB: fromNodeSqlite(raw) }) }
}

describe("getKrlVersion", () => {
	it("should start after the version previously used for every KRL", async () => {
		const { env } = fresh()

		expect(await getKrlVersion(env, CertificateType.User, "a")).toBe(2n)
	})

	it("should not change the version while the content is unchanged", async () => {
		const { env } = fresh()

		const first = await getKrlVersion(env, CertificateType.User, "a")

		expect(await getKrlVersion(env, CertificateType.User, "a")).toBe(first)
		expect(await getKrlVersion(env, CertificateType.User, "a")).toBe(first)
	})

	it("should increment the version whenever the content changes", async () => {
		const { env } = fresh()

		expect(await getKrlVersion(env, CertificateType.User, "a")).toBe(2n)
		expect(await getKrlVersion(env, CertificateType.User, "b")).toBe(3n)
		// returning to previous content is still a new version
		expect(await getKrlVersion(env, CertificateType.User, "a")).toBe(4n)
	})

	it("should keep separate versions for user and host KRLs", async () => {
		const { env } = fresh()

		expect(await getKrlVersion(env, CertificateType.User, "a")).toBe(2n)
		expect(await getKrlVersion(env, CertificateType.User, "b")).toBe(3n)
		expect(await getKrlVersion(env, CertificateType.Host, "a")).toBe(2n)
		expect(await getKrlVersion(env, CertificateType.User, "b")).toBe(3n)
	})

	it("should increment the version once when the same change is seen concurrently", async () => {
		const { raw, env } = fresh()
		await getKrlVersion(env, CertificateType.User, "a")

		const versions = await Promise.all(Array.from({ length: 10 }, () => getKrlVersion(env, CertificateType.User, "b")))

		expect(versions).toEqual(Array.from({ length: 10 }, () => 3n))
		expect(raw.prepare("SELECT version, digest FROM krl WHERE certificate_type = ?").get(CertificateType.User))
			.toEqual({ version: 3, digest: "b" })
	})
})
