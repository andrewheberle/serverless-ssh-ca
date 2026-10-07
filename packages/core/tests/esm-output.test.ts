import { describe, it, expect } from "vitest"
import { spawnSync } from "node:child_process"
import { mkdtempSync, rmSync } from "node:fs"
import { createRequire } from "node:module"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { z } from "zod"

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")

// Vitest resolves extensionless and directory imports itself, so the compiled
// output is loaded by a separate plain Node process to catch anything that only
// works under a bundler (missing extensions, CommonJS named exports, etc)
describe("compiled output", () => {
	it("should be importable by Node without a bundler", () => {
		// emitted inside the package so "type": "module" and node_modules resolution apply
		const outDir = mkdtempSync(join(packageRoot, ".esm-check-"))

		try {
			// typescript's "exports" map hides bin/tsc, so locate it via the package's "bin" field
			const require = createRequire(import.meta.url)
			const pkgJson = require.resolve("typescript/package.json")
			const { bin } = z.object({ bin: z.object({ tsc: z.string() }) }).parse(require(pkgJson))
			const tsc = join(dirname(pkgJson), bin.tsc)
			const build = spawnSync(process.execPath, [
				tsc,
				"-p", join(packageRoot, "tsconfig.json"),
				"--outDir", outDir,
				"--declaration", "false",
				"--declarationMap", "false",
				"--sourceMap", "false",
			], { encoding: "utf-8" })
			expect(build.status, build.stdout + build.stderr).toBe(0)

			const entry = pathToFileURL(join(outDir, "index.js")).href
			const script = `
				const mod = await import(${JSON.stringify(entry)})
				if (typeof mod.default?.fetch !== "function" || typeof mod.default?.scheduled !== "function") {
					throw new Error("default export is missing fetch or scheduled handlers")
				}
			`
			const run = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf-8" })
			expect(run.status, run.stderr).toBe(0)
		} finally {
			rmSync(outDir, { recursive: true, force: true })
		}
	}, 60_000)
})
