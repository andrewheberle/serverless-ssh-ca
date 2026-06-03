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

export interface SshCaBindings {
    DB: D1Database
    DB_CERTIFICATE_RETENTION: string
    PRIVATE_KEY: SecretsStoreSecret
    SSH_CERTIFICATE_EXTENSIONS: string
    SSH_CERTIFICATE_LIFETIME: string
    SSH_CERTIFICATE_INCLUDE_SELF?: string | boolean
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
