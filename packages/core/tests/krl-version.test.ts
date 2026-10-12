import { describe, it, expect, vi, afterEach } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { getKrlVersion } from "../src/db/index.js"
import { CertificateType } from "../src/db/types.js"
import { fromNodeSqlite } from "../src/node/sqlite.js"
import type { SshCaBindings } from "../src/types.js"
import { makeEnv } from "./env.js"

const fresh = (): { raw: DatabaseSync, env: SshCaBindings } => {
	const raw = new DatabaseSync(":memory:")
	return { raw, env: makeEnv({ DB: fromNodeSqlite(raw) }) }
}

// the version of the KRL for its content, without when it was generated
const versionOf = async (env: SshCaBindings, certificateType: CertificateType, digest: string): Promise<bigint> => {
	return (await getKrlVersion(env, certificateType, digest)).version
}

describe("getKrlVersion", () => {
	it("should start after the version previously used for every KRL", async () => {
		const { env } = fresh()

		expect(await versionOf(env, CertificateType.User, "a")).toBe(2n)
	})

	it("should not change the version while the content is unchanged", async () => {
		const { env } = fresh()

		const first = await versionOf(env, CertificateType.User, "a")

		expect(await versionOf(env, CertificateType.User, "a")).toBe(first)
		expect(await versionOf(env, CertificateType.User, "a")).toBe(first)
	})

	it("should increment the version whenever the content changes", async () => {
		const { env } = fresh()

		expect(await versionOf(env, CertificateType.User, "a")).toBe(2n)
		expect(await versionOf(env, CertificateType.User, "b")).toBe(3n)
		// returning to previous content is still a new version
		expect(await versionOf(env, CertificateType.User, "a")).toBe(4n)
	})

	it("should keep separate versions for user and host KRLs", async () => {
		const { env } = fresh()

		expect(await versionOf(env, CertificateType.User, "a")).toBe(2n)
		expect(await versionOf(env, CertificateType.User, "b")).toBe(3n)
		expect(await versionOf(env, CertificateType.Host, "a")).toBe(2n)
		expect(await versionOf(env, CertificateType.User, "b")).toBe(3n)
	})

	it("should increment the version once when the same change is seen concurrently", async () => {
		const { raw, env } = fresh()
		await versionOf(env, CertificateType.User, "a")

		const versions = await Promise.all(Array.from({ length: 10 }, () => versionOf(env, CertificateType.User, "b")))

		expect(versions).toEqual(Array.from({ length: 10 }, () => 3n))
		expect(raw.prepare("SELECT version, digest FROM krl WHERE certificate_type = ?").get(CertificateType.User))
			.toEqual({ version: 3, digest: "b" })
	})

	describe("generation date", () => {
		afterEach(() => {
			vi.useRealTimers()
		})

		it("should be the same for every KRL with the same version", async () => {
			const { env } = fresh()
			vi.useFakeTimers({ toFake: ["Date"] })
			vi.setSystemTime(new Date("2026-10-12T01:02:03.456Z"))

			const first = await getKrlVersion(env, CertificateType.User, "a")
			expect(first.generatedAt).toEqual(new Date("2026-10-12T01:02:03Z"))

			vi.setSystemTime(new Date("2026-10-12T05:00:00Z"))
			expect(await getKrlVersion(env, CertificateType.User, "a")).toEqual(first)
		})

		it("should be when the version changed", async () => {
			const { env } = fresh()
			vi.useFakeTimers({ toFake: ["Date"] })
			vi.setSystemTime(new Date("2026-10-12T01:00:00Z"))
			await getKrlVersion(env, CertificateType.User, "a")

			vi.setSystemTime(new Date("2026-10-12T02:00:00Z"))
			expect(await getKrlVersion(env, CertificateType.User, "b")).toEqual({ version: 3n, generatedAt: new Date("2026-10-12T02:00:00Z") })
		})

		it("should read a date set by SQLite as UTC", async () => {
			const { raw, env } = fresh()
			await getKrlVersion(env, CertificateType.User, "a")
			raw.prepare("UPDATE krl SET updated_at = '2026-01-02 03:04:05' WHERE certificate_type = ?").run(CertificateType.User)

			expect((await getKrlVersion(env, CertificateType.User, "a")).generatedAt).toEqual(new Date("2026-01-02T03:04:05Z"))
		})
	})
})
