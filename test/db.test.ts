import { describe, it, expect } from "vitest"
import { CertificateRecord, CertificateType, isRevoked, recordCertificate, runStatement, shouldRetry } from "../src/db"
import { env } from "cloudflare:workers"
import { createSelfSignedCertificate, identityForUser } from "sshpk"
import { userPrivateKey } from "./keys/ecdsa"

describe("shouldRetry", () => {
    it("retryable error", () => {
        expect(shouldRetry("D1 DB reset because its code was updated.", 1)).toBe(true)
    })

    it("retryable error with too many retries", () => {
        expect(shouldRetry("D1 DB reset because its code was updated.", 6)).toBe(false)
    })

    it("non-retryable error", () => {
        expect(shouldRetry("Exceeded maximum DB size.", 1)).toBe(false)
    })

    it("non-retryable error with too many retries (should never occur)", () => {
        expect(shouldRetry("Exceeded maximum DB size.", 6)).toBe(false)
    })
})

describe("runStatement", async () => {
    it("should return 1", async () => {
        const stmt = env.DB.prepare("SELECT 1 AS result")
        const res = await runStatement(stmt)

        expect(res.success).toBe(true)
        expect(res.results.length).toBe(1)
        expect(res.results[0]).toStrictEqual({result: 1})
    })
})

describe("isRevoked", async () => {
    it("not revoked", async () => {
        expect(await isRevoked(BigInt(1))).toBe(false)
    })
})

describe("recordCertificate", async () => {
	it("should record a certificate", async () => {
		const unixTimestamp = Date.now()
		const serial = Buffer.alloc(8)
		serial.writeBigUInt64BE(BigInt(unixTimestamp))

		const stmt = env.DB.prepare("SELECT * FROM certificates WHERE serial = ?").bind(`${unixTimestamp}`)
		const before = await runStatement<CertificateRecord>(stmt)
		expect(before.results.length).toBe(0)

		const key = userPrivateKey()

		const certificate = createSelfSignedCertificate(identityForUser("testuser"), key, {serial: serial})
		await recordCertificate(certificate, "testkeyid", CertificateType.User)

		const after = await runStatement<CertificateRecord>(stmt)
		expect(after.results.length).toBe(1)
		expect(after.results[0].serial).toBe(`${unixTimestamp}`)
		expect(after.results[0].key_id).toBe("testkeyid")
		expect(after.results[0].public_key).toBe(key.toPublic().toString("ssh"))
	})
})
