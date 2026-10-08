import { describe, it, expect, beforeEach } from "vitest"
import { DatabaseSync } from "node:sqlite"
import { fromNodeSqlite, splitStatements } from "../src/node/sqlite.js"
import type { CaDatabase, CaPreparedStatement } from "../src/types.js"

const tables = (db: DatabaseSync): unknown[] =>
	db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map(r => r.name)

describe("splitStatements", () => {
	it("should return a single statement unchanged", () => {
		expect(splitStatements("SELECT * FROM t WHERE a = ?")).toEqual([
			{ sql: "SELECT * FROM t WHERE a = ?", parameters: 1, named: false },
		])
	})

	it("should split on semicolons and count parameters per statement", () => {
		expect(splitStatements("CREATE TABLE a (x);\nINSERT INTO a (x) VALUES (?, ?);  INSERT INTO a (x) VALUES (?);")).toEqual([
			{ sql: "CREATE TABLE a (x)", parameters: 0, named: false },
			{ sql: "INSERT INTO a (x) VALUES (?, ?)", parameters: 2, named: false },
			{ sql: "INSERT INTO a (x) VALUES (?)", parameters: 1, named: false },
		])
	})

	it("should not split or count parameters inside strings, identifiers or comments", () => {
		const statements = splitStatements(`
			-- a comment; with a ?
			/* another; ? comment */
			SELECT 'it''s; ?', "a;?""b", \`c;?\`, [d;?] FROM t WHERE x = ?;
		`)
		expect(statements).toHaveLength(1)
		expect(statements[0]?.parameters).toBe(1)
		expect(statements[0]?.sql).toContain("[d;?] FROM t WHERE x = ?")
	})

	it("should drop empty statements", () => {
		expect(splitStatements(" ; -- nothing\n ;; SELECT 1; ")).toEqual([
			{ sql: "SELECT 1", parameters: 0, named: false },
		])
	})

	it("should flag numbered and named parameters", () => {
		expect(splitStatements("SELECT ?1; SELECT :a; SELECT @b; SELECT $c; SELECT ?").map(s => s.named))
			.toEqual([true, true, true, true, false])
	})

	it("should keep a trigger body as one statement", () => {
		const statements = splitStatements(`
			CREATE TEMP TRIGGER tr AFTER INSERT ON a BEGIN
				UPDATE a SET x = CASE WHEN x > 1 THEN 1 ELSE x END;
				DELETE FROM b;
			END;
			SELECT 1;
		`)
		expect(statements).toHaveLength(2)
		expect(statements[0]?.sql).toMatch(/^CREATE TEMP TRIGGER[\s\S]*DELETE FROM b;\s*END$/)
		expect(statements[1]?.sql).toBe("SELECT 1")
	})
})

describe("fromNodeSqlite", () => {
	let sqlite: DatabaseSync
	let db: CaDatabase

	beforeEach(() => {
		sqlite = new DatabaseSync(":memory:")
		sqlite.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT UNIQUE, flag INTEGER, data BLOB)")
		db = fromNodeSqlite(sqlite)
	})

	describe("statements", () => {
		it("should bind parameters and return rows", async () => {
			sqlite.exec("INSERT INTO t (name) VALUES ('a'), ('b')")

			const res = await db.prepare("SELECT name FROM t WHERE name = ?").bind("b").all()

			expect(res.success).toBe(true)
			expect(res.results).toEqual([{ name: "b" }])
			expect(res.meta?.changes).toBe(0)
		})

		it("should not change a statement when binding", async () => {
			sqlite.exec("INSERT INTO t (name) VALUES ('a'), ('b')")
			const stmt = db.prepare("SELECT name FROM t WHERE name = ?")

			const a = await stmt.bind("a").all()
			const b = await stmt.bind("b").all()

			expect(a.results).toEqual([{ name: "a" }])
			expect(b.results).toEqual([{ name: "b" }])
		})

		it("should report changes and the last row id", async () => {
			const insert = await db.prepare("INSERT INTO t (name) VALUES (?), (?)").bind("a", "b").run()
			const update = await db.prepare("UPDATE t SET flag = 1").run()
			const select = await db.prepare("SELECT * FROM t").all()

			expect(insert).toMatchObject({ success: true, meta: { changes: 2, last_row_id: 2 } })
			expect(update.meta?.changes).toBe(2)
			expect(select.meta?.changes).toBe(0)
		})

		it("should return rows from RETURNING", async () => {
			sqlite.exec("INSERT INTO t (name) VALUES ('a')")

			const res = await db.prepare("UPDATE t SET flag = ? WHERE name = ? RETURNING name, flag").bind(5, "a").all()

			expect(res.results).toEqual([{ name: "a", flag: 5 }])
			expect(res.meta?.changes).toBe(1)
		})

		it("should convert booleans and binary values like D1", async () => {
			await db.prepare("INSERT INTO t (name, flag, data) VALUES (?, ?, ?), (?, ?, ?)")
				.bind("a", true, new Uint8Array([1, 2]).buffer, "b", false, new Uint16Array([0x0403]))
				.run()

			const rows = sqlite.prepare("SELECT flag, hex(data) AS data FROM t ORDER BY name").all()

			expect(rows).toEqual([{ flag: 1, data: "0102" }, { flag: 0, data: "0304" }])
		})

		it("should reject undefined and other unsupported parameters", () => {
			const stmt = db.prepare("SELECT ?")

			expect(() => stmt.bind(undefined)).toThrow(TypeError)
			expect(() => stmt.bind({})).toThrow(TypeError)
		})

		it("should reject invalid SQL when executed", async () => {
			await expect(db.prepare("SELEC 1").all()).rejects.toThrow()
		})
	})

	describe("queries containing more than one statement", () => {
		// node:sqlite would otherwise only run the first statement, as used by the schema migrations
		it("should run every statement with its share of the parameters", async () => {
			await db.prepare(`
				CREATE TABLE m (id INTEGER PRIMARY KEY, name TEXT);
				INSERT INTO m (name) VALUES (?);
				INSERT INTO t (name, flag) VALUES (?, ?);
			`).bind("migration", "x", 7).run()

			expect(tables(sqlite)).toEqual(["m", "t"])
			expect(sqlite.prepare("SELECT name FROM m").all()).toEqual([{ name: "migration" }])
			expect(sqlite.prepare("SELECT name, flag FROM t").all()).toEqual([{ name: "x", flag: 7 }])
		})

		it("should return the rows of the last statement", async () => {
			const res = await db.prepare("INSERT INTO t (name) VALUES (?); SELECT name FROM t").bind("a").all()

			expect(res.results).toEqual([{ name: "a" }])
			expect(res.meta?.changes).toBe(1)
		})

		it("should roll back every statement if one fails", async () => {
			sqlite.exec("INSERT INTO t (name) VALUES ('dup')")

			await expect(db.prepare("CREATE TABLE m (x); INSERT INTO t (name) VALUES (?)").bind("dup").run()).rejects.toThrow()

			expect(tables(sqlite)).toEqual(["t"])
		})

		it("should reject a parameter count mismatch", async () => {
			await expect(db.prepare("SELECT ?; SELECT ?").bind(1).all()).rejects.toThrow(RangeError)
		})

		it("should reject named parameters", async () => {
			await expect(db.prepare("SELECT :a; SELECT 1").bind(1).all()).rejects.toThrow(/anonymous/)
		})

		it("should work inside an existing transaction", async () => {
			sqlite.exec("BEGIN")
			await db.prepare("INSERT INTO t (name) VALUES (?); INSERT INTO t (name) VALUES (?)").bind("a", "b").run()
			sqlite.exec("ROLLBACK")

			expect(sqlite.prepare("SELECT count(*) AS n FROM t").get()).toEqual({ n: 0 })
		})
	})

	describe("batch", () => {
		it("should run statements in order and return a result for each", async () => {
			const res = await db.batch([
				db.prepare("INSERT INTO t (name) VALUES (?)").bind("a"),
				db.prepare("INSERT INTO t (name) VALUES (?)").bind("b"),
				db.prepare("SELECT name FROM t ORDER BY name"),
			])

			expect(res).toHaveLength(3)
			expect(res[0]).toMatchObject({ success: true, meta: { changes: 1 } })
			expect(res[2]).toMatchObject({ results: [{ name: "a" }, { name: "b" }] })
		})

		it("should roll back every statement if one fails", async () => {
			await expect(db.batch([
				db.prepare("INSERT INTO t (name) VALUES (?)").bind("a"),
				db.prepare("INSERT INTO t (name) VALUES (?)").bind("a"),
			])).rejects.toThrow()

			expect(sqlite.prepare("SELECT count(*) AS n FROM t").get()).toEqual({ n: 0 })
		})

		it("should reject statements from another database", async () => {
			const other = fromNodeSqlite(new DatabaseSync(":memory:"))
			const foreign: CaPreparedStatement = {
				bind: () => foreign,
				all: async () => ({ success: true, results: [] }),
				run: async () => ({ success: true }),
			}

			await expect(db.batch([other.prepare("SELECT 1")])).rejects.toThrow(TypeError)
			await expect(db.batch([foreign])).rejects.toThrow(TypeError)
		})
	})

	describe("exec", () => {
		it("should run every statement", async () => {
			const res = await db.exec("CREATE TABLE a (x); CREATE TABLE b (y);")

			expect(res).toMatchObject({ count: 2 })
			expect(tables(sqlite)).toEqual(["a", "b", "t"])
		})
	})
})
