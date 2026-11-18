import { describe, it, expect, vi } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "../src/index.js"
import { fromNodeSqlite, secretFromString } from "../src/node/index.js"
import { makeEnv } from "./env.js"
import { key as ed25519Key } from "./keys/ed25519.js"

// A proof the requester sent that is not valid is logged as a warning (#600),
// but an error parsing a proof that is not one of those is a fault of the CA,
// so it is still logged as an error. Parsing throws nothing else today, so the
// proof module is mocked to
vi.mock("../src/proof.js", async (importOriginal) => {
	const original = await importOriginal<typeof import("../src/proof.js")>()
	return {
		...original,
		ProofOfPossession: class {
			constructor() {
				throw new TypeError("unexpected")
			}
		},
	}
})

describe("an unexpected error parsing a proof of possession", () => {
	it("should be refused with a 400 and logged as an error", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => undefined)
		const path = "/api/v4/user/certificates/1234"
		const ca = createSshCa(makeEnv({
			DB: fromNodeSqlite(new DatabaseSync(":memory:")),
			PRIVATE_KEY: secretFromString(ed25519Key.ca().privateKey),
			LOG_LEVEL: "error",
		}))

		const response = await ca.fetch(new Request(`http://example.com${path}`, { method: "DELETE", headers: { "Proof-Of-Possession": "1.SHA256:x.AAAA" } }))

		expect(response.status).toBe(400)
		expect(await response.json()).toMatchObject({ errors: [{ message: "proof of possession transform unhandled error", path: ["headers", "Proof-Of-Possession"] }] })
		expect(log).toHaveBeenCalledWith(expect.objectContaining({ level: "error", message: "proof of possession parsing error" }))
		log.mockRestore()
	})
})
