import path from "node:path"
import { cloudflareTest, readD1Migrations} from "@cloudflare/vitest-pool-workers"
import { defineConfig } from "vitest/config"

export default defineConfig(async () => {
    const oidcPort = process.env.OIDC_PORT ?? "4567"
    const oidcUrl = `http://localhost:${oidcPort}`
    const jwtAud = process.env.JWT_AUD ?? "audience"

	return {
		test: {
            globalSetup: [
                "./tests/setup/oidc-server.ts",
                "./tests/setup/proof.ts",
            ],
			coverage: {
				provider: "istanbul",
				include: ["src/**/*.ts"]
			}
		},
		plugins: [
			cloudflareTest({
				wrangler: {
					configPath: "./wrangler.jsonc",
				},
				miniflare: {
					compatibilityFlags: ["experimental", "nodejs_compat"],
					bindings: {
						"ISSUER_DN": "CN=SSH CA,O=Internet Widgets Pty Ltd,C=US",
						"SSH_CERTIFICATE_PRINCIPALS": "",
						"SSH_CERTIFICATE_INCLUDE_SELF": "true",
                        "JWT_JWKS_URL": `${oidcUrl}/jwks`,
                        "JWT_ISSUER": oidcUrl,
                        "JWT_ALGORITHMS": "RS256",
                        "JWT_AUD": jwtAud
					},
				},
			})
		]
	}
})
