import { env } from "cloudflare:workers"
import { IRequestStrict } from "itty-router"
import { JWTPayload } from "jose"
import { Key } from "sshpk"

// this is our custom request type for our router
export type AuthenticatedRequest = {
    email: string
    sub?: string
    public_key: Key
    identity?: JWTPayload
    principals?: string[]
    extensions?: typeof env.SSH_CERTIFICATE_EXTENSIONS
	lifetime: number
} & IRequestStrict

// this is the JSON payload of a certificate request
export type CertificateSignerPayload = {
    public_key: string
    identity?: string
    extensions?: typeof env.SSH_CERTIFICATE_EXTENSIONS
	lifetime?: number
}

export type CertificateSignerResponse = {
    certificate: string
}

// this is the expected JWT payload for a certificate request
export type CertificateRequestJWTPayload = {
    email: string
    [key: string]: string | string[]
} & JWTPayload

export type SSHExtension = {
    critical: boolean;
    name: string;
    data: Buffer<ArrayBuffer>
}
