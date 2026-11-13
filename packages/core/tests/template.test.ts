import { describe, expect, it } from "vitest"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { ConfigNames, parseConfig } from "../src/config.js"
import type { SshCaBindings } from "../src/types.js"

// the Worker the "Deploy to Cloudflare" button deploys (#624), which must
// keep working with the CA in this repo
const root = join(import.meta.dirname, "..", "..", "..")
const template = join(root, "template")

// parses JSON with comments and trailing commas, as wrangler.jsonc allows,
// without touching what is inside strings
const parseJsonc = (text: string): unknown => {
	let out = ""
	for (let i = 0; i < text.length; i++) {
		const char = text[i]
		if (char === "\"") {
			const end = text.indexOf("\"", i + 1)
			let close = end
			while (close !== -1 && text[close - 1] === "\\") {
				close = text.indexOf("\"", close + 1)
			}
			out += text.slice(i, close + 1)
			i = close
		} else if (char === "/" && text[i + 1] === "/") {
			i = text.indexOf("\n", i) - 1
		} else if (char === "/" && text[i + 1] === "*") {
			i = text.indexOf("*/", i) + 1
		} else {
			out += char
		}
	}
	return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"))
}

type Wrangler = {
	vars: Record<string, string>
	secrets_store_secrets: { binding: string }[]
	d1_databases: { binding: string }[]
	triggers: { crons: string[] }
}

type PackageJson = {
	cloudflare: { bindings: Record<string, { description: string }> }
	dependencies: Record<string, string>
	workspaces?: string[]
}

const wrangler = parseJsonc(readFileSync(join(template, "wrangler.jsonc"), "utf-8")) as Wrangler
const pkg = JSON.parse(readFileSync(join(template, "package.json"), "utf-8")) as PackageJson

describe("the Deploy to Cloudflare template", () => {
	it("should have settings the CA accepts", () => {
		// the database and key are only checked to be set, so placeholders do
		const env = { ...wrangler.vars, DB: {}, PRIVATE_KEY: {} } as unknown as SshCaBindings
		const result = parseConfig(env)

		expect(result.success ? "valid" : result.error.message).toBe("valid")
	})

	it("should only set settings the CA reads", () => {
		expect(Object.keys(wrangler.vars).filter((name) => !ConfigNames.includes(name))).toEqual([])
	})

	it("should describe every setting and binding the deploy form asks for, and nothing else", () => {
		const bindings = [
			...Object.keys(wrangler.vars),
			...wrangler.secrets_store_secrets.map((s) => s.binding),
			...wrangler.d1_databases.map((d) => d.binding),
		].sort()

		expect(Object.keys(pkg.cloudflare.bindings).sort()).toEqual(bindings)
		for (const [name, { description }] of Object.entries(pkg.cloudflare.bindings)) {
			expect(description, name).not.toBe("")
		}
	})

	it("should bind the key and database the CA uses, and run the daily cleanup", () => {
		expect(wrangler.secrets_store_secrets.map((s) => s.binding)).toEqual(["PRIVATE_KEY"])
		expect(wrangler.d1_databases.map((d) => d.binding)).toEqual(["DB"])
		expect(wrangler.triggers.crons).toHaveLength(1)
	})

	it("should pin the CA to the version of this repo, which release-please keeps up to date", () => {
		const core = JSON.parse(readFileSync(join(root, "packages", "core", "package.json"), "utf-8")) as { version: string }

		expect(pkg.dependencies["@andrewheberle/serverless-ssh-ca"]).toBe(core.version)
	})

	it("should be isolated from the workspaces, as the deploy button requires", () => {
		const rootPkg = JSON.parse(readFileSync(join(root, "package.json"), "utf-8")) as PackageJson

		expect(rootPkg.workspaces?.some((w) => w.startsWith("template"))).toBe(false)
		// a lockfile could not be kept in step by release-please
		expect(existsSync(join(template, "package-lock.json"))).toBe(false)
	})
})
