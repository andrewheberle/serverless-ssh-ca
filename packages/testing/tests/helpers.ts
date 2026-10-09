import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// a throwaway Ed25519 key used only by these tests
export const caKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfwAAAIhKaQBeSmkA
XgAAAAtzc2gtZWQyNTUxOQAAACDFbUIeQIJ5vZ5Jz9vXLnVCyXNhXadKJOubbov/hifMfw
AAAED8pydCkvNrysAmDUbVnT5goaFlepU9kjmIyP/O5G9HOMVtQh5Agnm9nknP29cudULJ
c2Fdp0ok65tui/+GJ8x/AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`

export const bindings: Record<string, string> = {
	ISSUER_DN: "CN=SSH CA,O=serverless-ssh-ca-testing,C=AU",
	JWT_JWKS_URL: "http://127.0.0.1:1/jwks",
	JWT_ISSUER: "http://127.0.0.1:1",
	JWT_AUD: "audience",
	JWT_ALGORITHMS: "RS256",
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: "groups",
	SSH_CERTIFICATE_LIFETIME: "24 hours",
	SSH_CERTIFICATE_EXTENSIONS: "permit-pty",
	SSH_HOST_CERTIFICATE_LIFETIME: "30 days",
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: "90 seconds",
	DB_CERTIFICATE_RETENTION: "1 year",
	LOG_LEVEL: "info",
}

export type TestFiles = {
	dir: string
	configFile: string
	portFile: string
	logFile: string
}

// write a configuration file to a new temporary directory
export const writeConfig = (overrides: Record<string, unknown> = {}): TestFiles => {
	const dir = mkdtempSync(join(tmpdir(), "ssh-ca-testing-"))
	const files = {
		dir,
		configFile: join(dir, "config.json"),
		portFile: join(dir, "port"),
		logFile: join(dir, "ca.log"),
	}

	writeFileSync(files.configFile, JSON.stringify({
		private_key: caKey,
		bindings,
		port_file: files.portFile,
		log_file: files.logFile,
		...overrides,
	}))

	return files
}
