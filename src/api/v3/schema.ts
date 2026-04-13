import z from "zod"
import {
	split,
	refineCertificateRequest,
	transformAuthorizationHeader,
	transformProofOfPossession,
	transformPublicKey,
	transformHostProofOfPossession,
	refineHostCertificateRequest,
	transformCertificate,
	refineHostCertificateRenewal,
	refineRevokeCertificate,
	transformIdentityToken,
} from "../../utils"
import {
	ConflictException,
	contentJson,
	ForbiddenException,
	InputValidationException,
	InternalServerErrorException,
	UnauthorizedException,
	UnprocessableEntityException,
} from "chanfana"
import { env } from "cloudflare:workers"
import { seconds } from "itty-time"

const openapiStringByte = z.base64()
	.transform((v) => {
		const a = z.util.base64ToUint8Array(v)
		return Buffer.from(
			a.buffer,
			a.byteOffset,
			a.length
		)
	})
	.openapi({ format: "byte" })

const proofOfPossession = z.string()
	.meta({
		description: "Proof of possession comprising of ${timestamp}.${fingerprint}.${signature}",
		example: "1765696780805.SHA256:79mq0wtpQMTvS4+Of8VzLN0qmYWNUyTXYmqKwhEgSLs.LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFHZ0FBQUFUWldOa2MyRXRjMmhoTWkxdWFYTjBjREkxTmdBQUFBaHVhWE4wY0RJMQpOZ0FBQUVFRUR6Ymk4OE10alBYSDFCb1JURU9HaS96aEc4QnhQNVZUUW5OQkFNMGZtMExtekErUUZkUlNVYVRFCkdNN2l0QjhINmZNZFAydlAxcElQcGUyOWVLQkJZd0FBQUFSbWFXeGxBQUFBQUFBQUFBWnphR0UxTVRJQUFBQmsKQUFBQUUyVmpaSE5oTFhOb1lUSXRibWx6ZEhBeU5UWUFBQUJKQUFBQUlHdmZVZGNDQkRXa3ZwL0ZHS3NkakgrRQpKZzZXN0EvWUJVZng2Z0srQ01raEFBQUFJUUQxOFd5cDNZejZ0eXNvdllXbEJHTXprRnlYbFRrSHM5blVVRXJqCkczNWVPQT09Ci0tLS0tRU5EIFNTSCBTSUdOQVRVUkUtLS0tLQo="
	})

const publicKey = openapiStringByte
	.transform(transformPublicKey)
	.meta({
		description: "SSH public key to sign",
		example: "ZWNkc2Etc2hhMi1uaXN0cDI1NiBBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkdNcFNKdHRmMEl0dE5DVmMyOFR6WEZSMUQweHZPM25wNjdWemVBUXNiZFpza3JEY1lqU2x3SjZIUERtVHBYYVUwbEVhWDlMNFloYy9jQ2YxTWU5RlRrPQo="
	})

const identityToken = z.string()
	.meta({
		description: "Identity Token JWT from OIDC IdP",
		example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzc1NzAzMDk1fQ.ri_neAWnhMNK3LzlsrBcQYymSM4yRjmNSZZSeZiXhrEqtEz6c3cXk0Esq765umGjpUsWcosL-OFrDJlyAjTDnhrd9oV08uc_CW0rQRsJIGEuRo3ryxkLdVu9mGoZWEUb9KwjGJrwxvr-0cPWx5jaDyKwJcqMvtV_bEITUD51sDB1Vm89QfYRO_pGJo2vrRzSvMjpUenRpwPay4lYIBxl41_4YpR9Rc6VrIZuYsjV2iqEZ4eBrygMA7zPR_hN7l7s95FddLOzj5NsK57VT4uLHwYohx2oqMzw3M-B9HsZIQin_9q61pZFQXepzJth0woXiZheU27llnfHX967PhNQyg"
	})
	.transform(transformIdentityToken)

const accessToken = z.string()
	.meta({
		description: "Access Token JWT from OIDC IdP",
		example: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzc1NzAzMDk1fQ.ri_neAWnhMNK3LzlsrBcQYymSM4yRjmNSZZSeZiXhrEqtEz6c3cXk0Esq765umGjpUsWcosL-OFrDJlyAjTDnhrd9oV08uc_CW0rQRsJIGEuRo3ryxkLdVu9mGoZWEUb9KwjGJrwxvr-0cPWx5jaDyKwJcqMvtV_bEITUD51sDB1Vm89QfYRO_pGJo2vrRzSvMjpUenRpwPay4lYIBxl41_4YpR9Rc6VrIZuYsjV2iqEZ4eBrygMA7zPR_hN7l7s95FddLOzj5NsK57VT4uLHwYohx2oqMzw3M-B9HsZIQin_9q61pZFQXepzJth0woXiZheU27llnfHX967PhNQyg"
	})
	.startsWith("Bearer ")
	.transform(transformAuthorizationHeader)

const krl = openapiStringByte
	.meta({ description: "Key Revocation List" })

const HeaderSchema = z.object({
	"Authorization": accessToken
})

const certificate = openapiStringByte
	.meta({ description: "Issued Certificate" })

export const CaPublicKeyEndpointSchema = {
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

export const UserCertificateRequestEndpointSchema = {
	security: [
		{
			oidcAuth: []
		}
	],
	request: {
		headers: HeaderSchema,
		body: contentJson(
			z.object({
				public_key: publicKey,
				proof: proofOfPossession
					.transform(transformProofOfPossession),
				identity: identityToken,
				extensions: z.array(z.string())
					.default(split(env.SSH_CERTIFICATE_EXTENSIONS))
					.meta({ description: "Extensions to include in the issued SSH certificate" }),
				lifetime: z.int()
					.min(seconds("5 minutes"))
					.max(seconds(env.SSH_CERTIFICATE_LIFETIME))
					.default(seconds(env.SSH_CERTIFICATE_LIFETIME))
					.meta({ description: "Lifetime of issued SSH certificate" }),
			})
				.superRefine(refineCertificateRequest)
				.openapi("User Certificate Request")
		)
	},
	responses: {
		"200": {
			description: "SSH User Certificate issued successfully",
			...contentJson(z.object({
				certificate: certificate,
			})
				.openapi("Certificate Response")
			)
		},
		...UnauthorizedException.schema(),
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
}

export const RevocationListEndpointSchema = {
	request: {
		params: z.object({
			certificateType: z.enum(["user", "host"])
		}),
	},
	responses: {
		"200": {
			description: "Returns an Open SSH Key Revocation List as BASE64 and an SSHSIG signature for verification",
			...contentJson(z.object({
				krl: krl,
				signature: z.string()
			})
				.openapi("Key Revocation List Response")
			)
		},
		...InternalServerErrorException.schema(),
	}
}

export const HostCertificateRequestEndpointSchema = {
	security: [
		{
			oidcAuth: []
		}
	],
	request: {
		headers: HeaderSchema,
		body: contentJson(
			z.object({
				public_key: publicKey,
				proof: proofOfPossession
					.transform(transformHostProofOfPossession),
				identity: identityToken,
				principals: z.array(z.string()).min(1)
					.meta({ description: "List of principals to include on the issued certificate" }),
				lifetime: z.int()
					.min(seconds("24 hours"))
					.max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
					.default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
					.meta({ description: "Lifetime of issued Host SSH certificate" }),
			})
				.superRefine(refineHostCertificateRequest)
				.openapi("Host Certificate Request")
		)
	},
	responses: {
		"200": {
			description: "SSH Host Certificate issued successfully",
			...contentJson(z.object({
				certificate: certificate,
			})
				.openapi("Certificate Response")
			)
		},
		...UnauthorizedException.schema(),
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
}

export const HostCertificateRenewEndpointSchema = {
	request: {
		body: contentJson(
			z.object({
				certificate: openapiStringByte
					.transform(transformCertificate)
					.meta({ description: "SSH certificate to renew" }),
				public_key: publicKey,
				proof: proofOfPossession
					.transform(transformHostProofOfPossession),
				lifetime: z.int()
					.min(seconds("24 hours"))
					.max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
					.default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
					.meta({ description: "Lifetime of renewed Host SSH certificate" }),
			})
				.superRefine(refineHostCertificateRenewal)
				.openapi("Host Certificate Renew")
		)
	},
	responses: {
		"200": {
			description: "SSH Host Certificate renewed successfully",
			...contentJson(z.object({
				certificate: certificate
			})
				.openapi("Certificate Response")
			),
		},
		...UnauthorizedException.schema(),
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
}

export const RevokeCertificateEndpointSchema = {
	request: {
		params: z.object({
			certificateType: z.enum(["user", "host"])
		}),
		body: contentJson(
			z.object({
				serial: z.bigint()
					.meta({ description: "Serial number of certificate to revoke" }),
				public_key: publicKey,
				proof: proofOfPossession
					.transform(transformProofOfPossession),
			})
				.openapi("Certificate Revocation")
				.superRefine(refineRevokeCertificate)
		)
	},
	responses: {
		"200": {
			description: "SSH certificate revoked successfully",
			...contentJson(z.object({
				revoked_at: z.iso.datetime(),
			})
				.openapi("Revocation Response")
			),
		},
		...UnauthorizedException.schema(),
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
		...ConflictException.schema()
	}
}
