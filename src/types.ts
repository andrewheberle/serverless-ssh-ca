import { env } from "cloudflare:workers"
import { JWTPayload } from "jose"

// this is the JSON payload of a certificate request
export type CertificateSignerPayload = {
    public_key: string
    identity: string
    extensions?: typeof env.SSH_CERTIFICATE_EXTENSIONS
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
