declare module "cloudflare:test" {
  interface ProvidedEnv extends Env {
    "SSH_CERTIFICATE_PRINCIPALS": "",
	"SSH_CERTIFICATE_INCLUDE_SELF": "false"
  }
}