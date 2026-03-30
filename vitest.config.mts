import path from "node:path"
import { cloudflareTest, readD1Migrations} from "@cloudflare/vitest-pool-workers"
import { defineConfig } from "vitest/config"

export default defineConfig(async () => {

	const migrationsPath = path.join(__dirname, "migrations");
	const migrations = await readD1Migrations(migrationsPath);

	return {
		test: {
			coverage: {
				provider: "istanbul",
				include: ["src/**/*.ts"]
			},
			setupFiles: ["./test/apply-migrations.ts"],
		},
		plugins: [
			cloudflareTest({
				wrangler: {
					configPath: "./wrangler.jsonc",
				},
				miniflare: {
					compatibilityFlags: ["experimental", "nodejs_compat"],
					bindings: {
						"SSH_CERTIFICATE_PRINCIPALS": "",
						"SSH_CERTIFICATE_INCLUDE_SELF": "false",
						"TEST_MIGRATIONS": migrations
					},
				},
			})
		]
	}
})
