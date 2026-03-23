import { cloudflareTest } from "@cloudflare/vitest-pool-workers"
import { defineConfig, Plugin } from "vitest/config"

function fixIstanbulBabelInterop(): Plugin {
  return {
    name: "fix-istanbul-babel-interop",
    transform(code, id) {
      if (!id.includes("coverage-istanbul/dist/provider")) return;
      // Replace the default import with a namespace import so Vite's SSR
      // transform doesn't wrap it in .default (which loses CJS exports)
      return code.replace(
        "import require$$0$3 from '@babel/core';",
        () => "import * as require$$0$3 from '@babel/core';",
      );
    },
  };
}

export default defineConfig({
	test: {
		coverage: {
			provider: "istanbul",
			include: ["src/**/*.ts"]
		}
	},
	plugins: [
		fixIstanbulBabelInterop(),
		cloudflareTest({
			wrangler: {
				configPath: "./wrangler.test.jsonc",
			},
			miniflare: {
				compatibilityFlags: ["experimental", "nodejs_compat"],
				bindings: {
					"PRIVATE_KEY": `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTrh5Brsk2pEY/l1HUv9iB633qsuPzf
GxVbZUi7LXKitJua4v4mZEpuQfCGXa2ZYJtIIDXm+m3YdLkbAYBElWcSAAAAwBqUjmkalI
5pAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOuHkGuyTakRj+XU
dS/2IHrfeqy4/N8bFVtlSLstcqK0m5ri/iZkSm5B8IZdrZlgm0ggNeb6bdh0uRsBgESVZx
IAAAAgenwTB1kprsmfs3e2PWGfZ4JDi+d5PTEMg6Rf3WgLZ+sAAAAmci1ncm91cFxhbmRy
ZXcuaGViZXJsZUBSR0ktVEo5OUY5aEpqeFUBAg==
-----END OPENSSH PRIVATE KEY-----`,
					"SSH_CERTIFICATE_PRINCIPALS": "",
					"SSH_CERTIFICATE_INCLUDE_SELF": "false",
				},
			},
		})
	]
})
