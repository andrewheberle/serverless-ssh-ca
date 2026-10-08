import type { DatabaseSync, SQLInputValue } from "node:sqlite"
import type { CaDatabase, CaDatabaseQueryResult, CaDatabaseResult, CaPreparedStatement } from "../types.js"

/**
 * A single SQL statement split from a larger query by {@link splitStatements}.
 */
export type SqlStatement = {
	/** The SQL of the statement, without its trailing `;` */
	sql: string
	/** The number of anonymous (`?`) parameters in the statement */
	parameters: number
	/** Whether the statement uses numbered or named parameters (`?1`, `:name`, `@name` or `$name`) */
	named: boolean
}

const isWordChar = (ch: string | undefined): boolean => ch !== undefined && /[A-Za-z0-9_$]/.test(ch)

/**
 * Split SQL that may contain several statements into individual statements.
 *
 * `node:sqlite` only compiles the first statement passed to `prepare()`,
 * whereas Cloudflare D1 runs them all, so queries are split here first. Quoted
 * strings and identifiers, comments and `CREATE TRIGGER ... BEGIN ... END`
 * bodies are not split. Statements containing nothing but whitespace or
 * comments are dropped.
 *
 * @param sql The SQL to split
 * @returns The statements found in `sql`, see {@link SqlStatement}
 */
export const splitStatements = (sql: string): SqlStatement[] => {
	const statements: SqlStatement[] = []

	let start = 0
	let parameters = 0
	let named = false
	let hasTokens = false
	let words: string[] = []
	let depth = 0

	const push = (end: number): void => {
		if (hasTokens) {
			statements.push({ sql: sql.slice(start, end).trim(), parameters, named })
		}
		start = end + 1
		parameters = 0
		named = false
		hasTokens = false
		words = []
		depth = 0
	}

	// true if the current statement is CREATE [TEMP|TEMPORARY] TRIGGER, whose body may contain ";"
	const inTrigger = (): boolean => words[0] === "CREATE" && (words[1] === "TRIGGER" || words[2] === "TRIGGER")

	let i = 0
	while (i < sql.length) {
		const ch = sql[i]
		const next = sql[i + 1]

		// comments
		if (ch === "-" && next === "-") {
			const end = sql.indexOf("\n", i)
			i = end === -1 ? sql.length : end + 1
			continue
		}
		if (ch === "/" && next === "*") {
			const end = sql.indexOf("*/", i + 2)
			i = end === -1 ? sql.length : end + 2
			continue
		}

		// whitespace
		if (ch === undefined || /\s/.test(ch)) {
			i++
			continue
		}

		// end of statement
		if (ch === ";" && depth === 0) {
			push(i)
			i++
			continue
		}

		hasTokens = true

		// quoted strings and identifiers, where a doubled quote is an escaped quote
		if (ch === "'" || ch === "\"" || ch === "`" || ch === "[") {
			const close = ch === "[" ? "]" : ch
			let j = i + 1
			while (j < sql.length) {
				if (sql[j] === close) {
					if (close !== "]" && sql[j + 1] === close) {
						j += 2
						continue
					}
					break
				}
				j++
			}
			i = j + 1
			continue
		}

		// parameters
		if (ch === "?") {
			let j = i + 1
			while (j < sql.length && /[0-9]/.test(sql[j] ?? "")) {
				j++
			}
			if (j === i + 1) {
				parameters++
			} else {
				named = true
			}
			i = j
			continue
		}
		if ((ch === ":" || ch === "@" || ch === "$") && isWordChar(next)) {
			named = true
			i++
			while (isWordChar(sql[i])) {
				i++
			}
			continue
		}

		// keywords and identifiers
		if (isWordChar(ch)) {
			let j = i
			while (isWordChar(sql[j])) {
				j++
			}
			const word = sql.slice(i, j).toUpperCase()
			if (words.length < 3) {
				words.push(word)
			}
			if (inTrigger()) {
				if (word === "BEGIN" || word === "CASE") {
					depth++
				} else if (word === "END" && depth > 0) {
					depth--
				}
			}
			i = j
			continue
		}

		i++
	}

	push(sql.length)

	return statements
}

/**
 * Convert a value bound to a statement into one `node:sqlite` accepts, using
 * the same conversions as Cloudflare D1.
 */
const toSqlValue = (value: unknown): SQLInputValue => {
	if (value === null || typeof value === "number" || typeof value === "bigint" || typeof value === "string") {
		return value
	}
	if (typeof value === "boolean") {
		return value ? 1 : 0
	}
	if (value instanceof ArrayBuffer) {
		return new Uint8Array(value)
	}
	if (ArrayBuffer.isView(value)) {
		return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
	}
	throw new TypeError(`unsupported type for SQL parameter: ${value === undefined ? "undefined" : typeof value}`)
}

const toNumber = (value: unknown): number => {
	if (typeof value === "number") {
		return value
	}
	if (typeof value === "bigint") {
		return Number(value)
	}
	throw new TypeError(`expected a number from SQLite but got ${typeof value}`)
}

// counters used to report D1 style metadata for any statement
const counters = (db: DatabaseSync): { changes: number, lastRowId: number } => {
	const row = db.prepare("SELECT total_changes() AS changes, last_insert_rowid() AS last_row_id").get()
	return { changes: toNumber(row?.changes), lastRowId: toNumber(row?.last_row_id) }
}

let savepointId = 0

// run fn atomically, using a savepoint so it also works inside an existing transaction
const atomically = <T>(db: DatabaseSync, fn: () => T): T => {
	const name = `serverless_ssh_ca_${savepointId++}`
	db.exec(`SAVEPOINT ${name}`)
	try {
		const result = fn()
		db.exec(`RELEASE ${name}`)
		return result
	} catch (err) {
		db.exec(`ROLLBACK TO ${name}`)
		db.exec(`RELEASE ${name}`)
		throw err
	}
}

class NodeSqliteStatement implements CaPreparedStatement {
	readonly db: DatabaseSync
	private readonly sql: string
	private readonly values: readonly SQLInputValue[]

	constructor(db: DatabaseSync, sql: string, values: readonly SQLInputValue[] = []) {
		this.db = db
		this.sql = sql
		this.values = values
	}

	bind(...values: unknown[]): NodeSqliteStatement {
		return new NodeSqliteStatement(this.db, this.sql, values.map(toSqlValue))
	}

	async all(): Promise<CaDatabaseQueryResult> {
		return this.execute()
	}

	async run(): Promise<CaDatabaseResult> {
		const { success, meta } = this.execute()
		return { success, meta }
	}

	// executes synchronously so no other query can run part way through
	execute(): CaDatabaseQueryResult {
		const started = performance.now()
		const before = counters(this.db)
		const results = this.query()
		const after = counters(this.db)

		return {
			success: true,
			results,
			meta: {
				changes: after.changes - before.changes,
				last_row_id: after.lastRowId,
				duration: performance.now() - started,
			},
		}
	}

	private query(): unknown[] {
		const statements = splitStatements(this.sql)
		if (statements.length <= 1) {
			return this.db.prepare(this.sql).all(...this.values)
		}

		if (statements.some(s => s.named)) {
			throw new Error("queries containing more than one statement only support anonymous (?) parameters")
		}
		const expected = statements.reduce((total, s) => total + s.parameters, 0)
		if (expected !== this.values.length) {
			throw new RangeError(`query expects ${expected} parameters but ${this.values.length} were bound`)
		}

		// give each statement its share of the bound values, returning the rows of the last statement
		return atomically(this.db, () => {
			let offset = 0
			let results: unknown[] = []
			for (const statement of statements) {
				const values = this.values.slice(offset, offset + statement.parameters)
				offset += statement.parameters
				results = this.db.prepare(statement.sql).all(...values)
			}
			return results
		})
	}
}

/**
 * Use a Node.js `node:sqlite` database as the CA's database.
 *
 * The returned object behaves like a Cloudflare D1 binding: queries containing
 * several statements are run in full (see {@link splitStatements}) and
 * {@link CaDatabase.batch} is atomic. The database's schema is created and
 * migrated automatically when the CA first uses it.
 *
 * @example
 * ```ts
 * import { DatabaseSync } from "node:sqlite"
 * import { fromNodeSqlite } from "@andrewheberle/serverless-ssh-ca/node"
 *
 * const DB = fromNodeSqlite(new DatabaseSync("ssh-ca.sqlite"))
 * ```
 *
 * @param db An open `node:sqlite` database
 * @returns A database for the `DB` binding, see {@link CaDatabase}
 */
export const fromNodeSqlite = (db: DatabaseSync): CaDatabase => ({
	prepare: (query: string): CaPreparedStatement => new NodeSqliteStatement(db, query),
	batch: async (statements: CaPreparedStatement[]): Promise<CaDatabaseQueryResult[]> => {
		const owned = statements.map(s => {
			if (!(s instanceof NodeSqliteStatement) || s.db !== db) {
				throw new TypeError("batch statements must be prepared by the same database")
			}
			return s
		})
		return atomically(db, () => owned.map(s => s.execute()))
	},
	exec: async (query: string): Promise<{ count: number, duration: number }> => {
		const started = performance.now()
		db.exec(query)
		return { count: splitStatements(query).length, duration: performance.now() - started }
	},
})
