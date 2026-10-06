import { describe, it, expect } from "vitest"
import { dbCleanup } from "../src/db"
import { makeEnv } from "./env"

// a D1 binding that records any use of it
const trackedDatabase = (): { db: D1Database, used: PropertyKey[] } => {
	const used: PropertyKey[] = []
	const db = new Proxy({}, {
		get(_, prop) {
			used.push(prop)
			throw new Error("database should not be used")
		},
	}) as unknown as D1Database
	return { db, used }
}

describe("dbCleanup", () => {
	it("should not touch the database when retention is infinite", async () => {
		const { db, used } = trackedDatabase()

		await dbCleanup(makeEnv({ DB: db, DB_CERTIFICATE_RETENTION: "infinite" }))

		expect(used).toEqual([])
	})

	it("should use the database when retention is limited", async () => {
		const { db, used } = trackedDatabase()

		await dbCleanup(makeEnv({ DB: db, DB_CERTIFICATE_RETENTION: "1 year" }))

		expect(used).not.toEqual([])
	})
})
