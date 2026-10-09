import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { formatArgs, formatRequest } from "../src/format.js"
import { FAULT_MESSAGE, isFault, LogFile } from "../src/log.js"

describe("formatArgs", () => {
	it.each([
		{ name: "strings", args: ["a", "b"], want: "a b" },
		{ name: "objects as JSON", args: [{ level: "INFO", message: "m" }], want: `{"level":"INFO","message":"m"}` },
		{ name: "bigints as strings", args: [{ serial: 10n }], want: `{"serial":"10"}` },
	])("should format $name", ({ args, want }) => {
		expect(formatArgs(args)).toBe(want)
	})

	it("should format errors with their name and message", () => {
		const parsed: unknown = JSON.parse(formatArgs([{ error: new TypeError("bad") }]))

		expect(parsed).toMatchObject({ error: { name: "TypeError", message: "bad" } })
	})
})

describe("formatRequest", () => {
	it.each([
		{ name: "accepted", status: 200, want: { level: "info", message: "harness request", method: "GET", url: "/a", status: 200 } },
		{ name: "rejected", status: 400, want: { level: "info", message: "harness request", method: "GET", url: "/a", status: 400, body: "nope" } },
	])("should format a $name request", ({ status, want }) => {
		expect(JSON.parse(formatRequest("GET", "/a", status, "nope"))).toEqual(want)
	})
})

describe("isFault", () => {
	it.each([
		{ name: "unhandled error", line: `{"level":"ERROR","message":"unhandled error"}`, want: true },
		{ name: "router error", line: `{"level":"ERROR","message":"unexpected error from router"}`, want: true },
		{ name: "database error", line: `{"level":"ERROR","message":"there was a problem adding issued certificate to database"}`, want: true },
		{ name: "lower case level", line: `{"level":"error","message":"unhandled error"}`, want: true },
		{ name: "rejected request", line: `{"level":"ERROR","message":"token subjects did not match"}`, want: false },
		{ name: "info about the database", line: `{"level":"INFO","message":"database migrated"}`, want: false },
		{ name: "not JSON", line: "unhandled error", want: false },
		{ name: "JSON without a level", line: `{"message":"unhandled error"}`, want: false },
	])("should report $name as $want", ({ line, want }) => {
		expect(isFault(line)).toBe(want)
	})
})

describe("LogFile", () => {
	let dir: string
	let log: LogFile

	const lines = (): unknown[] => readFileSync(log.path, "utf-8").trim().split("\n").map(l => JSON.parse(l))

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "ssh-ca-testing-"))
		log = new LogFile(join(dir, "ca.log"))
	})

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true })
	})

	it("should write CA lines as they are", () => {
		log.write(`{"level":"INFO","message":"issued"}`)

		expect(lines()).toEqual([{ level: "INFO", message: "issued" }])
	})

	it("should follow a CA fault with a harness fault", () => {
		const line = `{"level":"ERROR","message":"unhandled error"}`
		log.write(line)

		expect(lines()).toEqual([
			{ level: "ERROR", message: "unhandled error" },
			{ level: "error", message: FAULT_MESSAGE, line },
		])
	})

	it("should write harness faults with a harness prefix", () => {
		log.fault("request failed", new Error("boom"))

		expect(lines()).toMatchObject([{ level: "error", message: "harness request failed", error: { message: "boom" } }])
	})
})
