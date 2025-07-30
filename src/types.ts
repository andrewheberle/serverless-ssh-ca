import { JWTPayload } from "jose"

export type CertificateSignerPayload = {
    public_key: string
    extensions?: string[]
	lifetime?: number
}

export type CertificateSignerResponse = {
    certificate: string
}

export type CertificateRequestJWTPayload = {
    email?: string
    principals?: string[]
} & JWTPayload
