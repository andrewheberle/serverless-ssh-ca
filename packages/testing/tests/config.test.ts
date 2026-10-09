import { rmSync, writeFileSync } from "node:fs"
import { afterEach, describe, expect, it } from "vitest"
import { readConfig } from "../src/config.js"
import { bindings, caKey, writeConfig, type TestFiles } from "./helpers.js"

describe("readConfig", () => {
	let files: TestFiles | undefined

	afterEach(() => {
		if (files !== undefined) {
			rmSync(files.dir, { recursive: true, force: true })
			files = undefined
		}
	})

	it("should read a valid configuration", async () => {
		files = writeConfig()

		await expect(readConfig(files.configFile)).resolves.toEqual({
			private_key: caKey,
			bindings,
			port_file: files.portFile,
			log_file: files.logFile,
		})
	})

	it.each([
		{ name: "missing private_key", overrides: { private_key: undefined }, error: /private_key/ },
		{ name: "empty private_key", overrides: { private_key: "" }, error: /private_key/ },
		{ name: "non-string binding", overrides: { bindings: { LOG_LEVEL: 1 } }, error: /bindings/ },
		{ name: "missing port_file", overrides: { port_file: undefined }, error: /port_file/ },
		{ name: "missing log_file", overrides: { log_file: undefined }, error: /log_file/ },
	])("should reject a configuration with $name", async ({ overrides, error }) => {
		files = writeConfig(overrides)

		await expect(readConfig(files.configFile)).rejects.toThrow(error)
	})

	it("should reject a file that is not JSON", async () => {
		files = writeConfig()
		writeFileSync(files.configFile, "not json")

		await expect(readConfig(files.configFile)).rejects.toThrow(/parsing/)
	})
})
