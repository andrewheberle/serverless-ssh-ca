import type { SshCaBindings } from "../src/types"

const port = parseInt(process.env.OIDC_PORT ?? "4567")

export const makeEnv = (overrides: Partial<SshCaBindings> = {}): SshCaBindings => ({
    DB: null as unknown as D1Database,
    PRIVATE_KEY: null as unknown as SecretsStoreSecret,
    ISSUER_DN: "CN=SSH CA,O=Internet Widgets Pty Ltd,C=US",
    JWT_JWKS_URL: `http://localhost:${port}/jwks`,
    JWT_AUD: process.env.JWT_AUD ?? "audience",
    JWT_ISSUER: `http://localhost:${port}`,
    JWT_ALGORITHMS: "RS256",
    JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: "groups",
    SSH_CERTIFICATE_LIFETIME: "24 hours",
    SSH_CERTIFICATE_PRINCIPALS: "ssh-admin",
    SSH_CERTIFICATE_INCLUDE_SELF: false,
    SSH_CERTIFICATE_EXTENSIONS: "permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc",
    SSH_HOST_CERTIFICATE_ALLOWED_EMAILS: undefined,
    SSH_HOST_CERTIFICATE_ALLOWED_ROLES: undefined,
    SSH_HOST_CERTIFICATE_LIFETIME: "30 days",
    CERTIFICATE_REQUEST_TIME_SKEW_MAX: "90 seconds",
    DB_CERTIFICATE_RETENTION: "1 year",
    LOG_LEVEL: "info",
    ...overrides
})

export const env = makeEnv()
