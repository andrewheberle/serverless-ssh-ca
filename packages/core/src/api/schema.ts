import z from "zod"
import {
	refineSubjectKey,
	transformPublicKey,
} from "../utils.js"
import {
	contentJson,
	InternalServerErrorException,
} from "chanfana"
import { CertificateType } from "../db/types.js"

/**
 * Returns the name of a {@link CertificateType} as used in API paths and logs
 * @param certificateType The type of certificate
 * @returns "user" or "host"
 */
export const certificateTypeName = (certificateType: CertificateType): "user" | "host" => {
	switch (certificateType) {
		case CertificateType.User:
			return "user"
		case CertificateType.Host:
			return "host"
		default: {
			const unknownType: never = certificateType
			throw new Error(`unknown certificate type: ${String(unknownType)}`)
		}
	}
}

/**
 * Returns the OpenAPI tag that groups the endpoints for a {@link CertificateType}
 * @param certificateType The type of certificate
 * @returns "User" or "Host"
 */
export const certificateTypeTag = (certificateType: CertificateType): "User" | "Host" => {
	switch (certificateType) {
		case CertificateType.User:
			return "User"
		case CertificateType.Host:
			return "Host"
		default: {
			const unknownType: never = certificateType
			throw new Error(`unknown certificate type: ${String(unknownType)}`)
		}
	}
}

export const openapiStringByte = z.base64()
	.transform((v) => {
		const a = z.util.base64ToUint8Array(v)
		return Buffer.from(
			a.buffer,
			a.byteOffset,
			a.length
		)
	})
	.openapi({ format: "byte" })

export const subjectPublicKey = openapiStringByte
	.transform(transformPublicKey)
	.superRefine(refineSubjectKey)
	.meta({
		description: "SSH public key to sign, as the BASE64 encoding of its OpenSSH text form (such as `ecdsa-sha2-nistp256 AAAA... comment`), not of the binary key",
		example: "ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkdNcFNKdHRmMEl0dE5DVmMyOFR6WEZSMUQweHZPM25wNjdWemVBUXNiZFpza3JEY1lqU2x3SjZIUERtVHBYYVUwbEVhWDlMNFloYy9jQ2YxTWU5RlRrPQo="
	})

// tokens are only checked to be strings here, as they are verified together
// once the request is valid (see authenticate in requester.ts)
export const identityToken = z.string()
	.meta({
		description: "Identity Token JWT from OIDC IdP",
		example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzc1NzAzMDk1fQ.ri_neAWnhMNK3LzlsrBcQYymSM4yRjmNSZZSeZiXhrEqtEz6c3cXk0Esq765umGjpUsWcosL-OFrDJlyAjTDnhrd9oV08uc_CW0rQRsJIGEuRo3ryxkLdVu9mGoZWEUb9KwjGJrwxvr-0cPWx5jaDyKwJcqMvtV_bEITUD51sDB1Vm89QfYRO_pGJo2vrRzSvMjpUenRpwPay4lYIBxl41_4YpR9Rc6VrIZuYsjV2iqEZ4eBrygMA7zPR_hN7l7s95FddLOzj5NsK57VT4uLHwYohx2oqMzw3M-B9HsZIQin_9q61pZFQXepzJth0woXiZheU27llnfHX967PhNQyg"
	})

export const accessToken = z.string()
	.meta({
		description: "Bearer access token from the OIDC IdP, as `Bearer <token>`. This is the same header as the `oidcAuth` security scheme, and is also declared here for generated clients",
		example: "Bearer eyJ..."
	})

export const krl = openapiStringByte
	.meta({ description: "The OpenSSH Key Revocation List in its binary format, BASE64 encoded. Its comment is the certificate type it revokes, exactly `user` or `host`, and is covered by the signature, so check it matches the type requested. CAs before API version 4.2.0 leave the comment empty" })

export const certificate = openapiStringByte
	.meta({ description: "Issued certificate, as the BASE64 encoding of its OpenSSH text form (such as `ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA...`), not of the binary certificate" })

export const CaPublicKeyEndpointSchema = {
	tags: ["CA"],
	summary: "Get the CA public key",
	description: "Returns the public key of the SSH Certificate Authority in OpenSSH format, for use in `TrustedUserCAKeys` on SSH servers or `@cert-authority` entries in `known_hosts` on SSH clients.",
	responses: {
		"200": {
			content: {
				"text/plain": {
					schema: z.string()
				}
			},
			description: "Returns SSH Certificate Authority Public Key",
		},
		...InternalServerErrorException.schema(),
	}
}

export const createRevocationListEndpointSchema = (certificateType: CertificateType) => ({
	tags: [certificateTypeTag(certificateType)],
	summary: `Get the Key Revocation List for ${certificateTypeName(certificateType)} certificates`,
	description: `Returns the OpenSSH Key Revocation List (KRL) of revoked ${certificateTypeName(certificateType)} certificates issued by this CA, along with an SSHSIG signature made by the CA key so the KRL can be verified before use.`,
	responses: {
		"200": {
			description: `Returns an Open SSH Key Revocation List of revoked ${certificateTypeName(certificateType)} certificates as BASE64 and an SSHSIG signature for verification`,
			...contentJson(z.object({
				krl: krl,
				signature: z.string()
					.meta({ description: "Armored SSHSIG signature (`-----BEGIN SSH SIGNATURE-----`) made by the CA key over the decoded KRL bytes, with the SHA-512 hash and the `krl@com.github.serverless-ssh-ca.andrewheberle` namespace. It is not BASE64 encoded again" })
			})
				.openapi("Key Revocation List Response")
			)
		},
		...InternalServerErrorException.schema(),
	}
})
