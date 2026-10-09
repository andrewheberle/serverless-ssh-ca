import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

// the unit tests run before the workspace is built, so the CA is loaded from
// its source rather than the package's dist output
const core = (path: string): string => fileURLToPath(new URL(`../core/src/${path}`, import.meta.url))

export default defineConfig({
	resolve: {
		alias: [
			{ find: /^@andrewheberle\/serverless-ssh-ca\/node$/, replacement: core("node/index.ts") },
			{ find: /^@andrewheberle\/serverless-ssh-ca$/, replacement: core("index.ts") },
		],
	},
	test: {
		include: ["tests/**/*.test.ts"],
		coverage: {
			include: ["src/**/*.ts"],
		},
	},
})
