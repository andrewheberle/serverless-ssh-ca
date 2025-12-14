import {
	defineWorkersConfig,
} from "@cloudflare/vitest-pool-workers/config"

export default defineWorkersConfig({
	esbuild: {
		target: "esnext",
	},
	test: {
		coverage: {
			provider: "istanbul",
		},
		poolOptions: {
			workers: {
				singleWorker: true,
				wrangler: {
					configPath: "../wrangler.jsonc",
				},
				miniflare: {
					compatibilityFlags: ["experimental", "nodejs_compat"],
					secretsStoreSecrets: {
						PRIVATE_KEY: {
							store_id: "demo",
							secret_name: "ssh-ca-private-key"
						}
					}
				},
			},
		},
	},
})