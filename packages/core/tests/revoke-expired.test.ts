import { describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { generateRequestProof } from "./helpers/proof.js"
import { key as ed25519Key } from "./keys/ed25519.js"
import { key as ecdsaKey } from "./keys/ecdsa.js"

// only admins are refused because a certificate has expired, so the database
// is mocked to give that result to a key holder, which the API must treat as
// a fault rather than an answer for the client
vi.mock("../src/db/index.js", async (importOriginal) => {
	const original = await importOriginal<typeof import("../src/db/index.js")>()
	return {
		...original,
		revokeCertificate: vi.fn(async () => await Promise.resolve({ kind: "expired" as const })),
	}
})

describe("revocation by a key holder", () => {
	it("should return 500 and log why if the certificate is reported as expired", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const path = "/api/v4/user/certificates/1234"
		const ca = createSshCa(makeEnv({
			DB: fromNodeSqlite(new DatabaseSync(":memory:")),
			PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
			LOG_LEVEL: "error",
		}))

		const response = await ca.fetch(new Request(`http://example.com${path}`, {
			method: "DELETE",
			headers: { "Proof-Of-Possession": generateRequestProof(ecdsaKey.user(), "DELETE", path) },
		}))

		expect(response.status).toBe(500)
		expect(await response.json()).toEqual({ success: false, result: null, errors: [{ code: 7009, message: "Internal Error" }] })
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: "revocation by a key holder was refused as the certificate has expired" }))
		log.mockRestore()
	})
})
