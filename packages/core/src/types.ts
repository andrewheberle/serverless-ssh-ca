import { JWTPayload } from "jose"

// this is the JSON payload of a certificate request
export type CertificateSignerPayload = {
    public_key: string
    identity: string
    extensions?: string[]
	lifetime?: number
    nonce?: string
}

export type CertificateSignerResponse = {
    certificate: string
}

// this is the expected JWT payload for a certificate request
export type CertificateRequestJWTPayload = {
    email: string
    sub: string
    [key: string]: string | string[]
} & JWTPayload

export type SSHExtension = {
    critical: boolean;
    name: string;
    data: Buffer<ArrayBuffer>
}

/**
 * The subset of a Cloudflare D1 database binding used by the CA.
 *
 * A Workers `D1Database` binding satisfies this structurally, so the package
 * does not need to depend on `@cloudflare/workers-types`.
 */
export interface CaDatabase {
    prepare(query: string): unknown
    batch(statements: never[]): Promise<unknown>
    exec(query: string): Promise<unknown>
}

/**
 * The subset of a Cloudflare Secrets Store binding used to load the CA private key.
 *
 * A Workers `SecretsStoreSecret` binding satisfies this structurally.
 */
export interface CaSecret {
    get(): Promise<string>
}

/**
 * The bindings (environment) the CA expects, see {@link CaDatabase} and
 * {@link CaSecret} for the non-string bindings.
 */
export interface SshCaBindings {
    DB: CaDatabase
    DB_CERTIFICATE_RETENTION: string
    PRIVATE_KEY: CaSecret
    SSH_CERTIFICATE_EXTENSIONS: string
    SSH_CERTIFICATE_LIFETIME: string
    SSH_CERTIFICATE_INCLUDE_SELF?: string | boolean
    SSH_CERTIFICATE_INCLUDE_SELF_EMAIL?: string | boolean
    SSH_CERTIFICATE_PRINCIPALS?: string | string[]
    SSH_HOST_CERTIFICATE_LIFETIME: string
    SSH_HOST_CERTIFICATE_ALLOWED_EMAILS?: string | string[]
    SSH_HOST_CERTIFICATE_ALLOWED_ROLES?: string | string[]
    ISSUER_DN: string
	JWT_JWKS_URL: string
	JWT_AUD?: string | string[]
	JWT_ISSUER: string
	JWT_ALGORITHMS: string | string[]
	JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM: string
	CERTIFICATE_REQUEST_TIME_SKEW_MAX: string
	LOG_LEVEL?: string
}
