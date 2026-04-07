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
} from "../../utils"
import {
	contentJson,
	ForbiddenException,
	InputValidationException,
	InternalServerErrorException,
	UnprocessableEntityException,
} from "chanfana"
import { env } from "cloudflare:workers"
import { seconds } from "itty-time"

export const HeaderSchema = z.object({
	"Authorization": z.string()
		.meta({ description: "Access Token JWT from OIDC IdP" })
		.startsWith("Bearer ")
		.transform(transformAuthorizationHeader)

})

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
				public_key: z.base64()
					.transform(transformPublicKey)
					.meta({ description: "SSH public key to sign" }),
				proof: z.string()
					.transform(transformProofOfPossession)
					.meta({ description: "Proof of possession comprising of ${timestamp}.${fingerprint}.${format}:${signature}" }),
				identity: z.string()
					.meta({ description: "Identity Token JWT from OIDC IdP" }),
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
				certificate: z.string(),
			})
				.openapi("Certificate Response")
			)
		},
		"401": {
			description: "Access to the endpoint is Unauthorized",
			...contentJson(z.object({
				error: z.literal("Unauthorized")
			}))
		},
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
}

export const RevocationListEndpointSchema = {
	responses: {
		"200": {
			description: "Returns an Open SSH Key Revocation List as BASE64 and an SSHSIG signature for verification",
			...contentJson(z.object({
				krl: z.stringFormat("byte", (val: string): boolean => {
					try {
						atob(val)
						return true
					} catch (err) {
						return false
					}
				})
					.meta({ title: "Key Revocation List" }),
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
				public_key: z.base64()
					.transform(transformPublicKey)
					.meta({ description: "SSH public key to sign" }),
				proof: z.string()
					.transform(transformHostProofOfPossession)
					.meta({ description: "Proof of possession comprising of ${timestamp}.${fingerprint}.${format}:${signature}" }),
				identity: z.string()
					.meta({ description: "Identity Token JWT from OIDC IdP" }),
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
				certificate: z.string(),
			})
				.openapi("Certificate Response")
			)
		},
		"401": {
			description: "Access to the endpoint is Unauthorized",
			...contentJson(z.object({
				status: z.literal(401),
				error: z.literal("Unauthorized")
			}))
		},
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
				certificate: z.base64()
					.transform(transformCertificate)
					.meta({ description: "SSH certificate to renew" }),
				public_key: z.base64()
					.transform(transformPublicKey)
					.meta({ description: "SSH public key of certificate to be renewed" }),
				proof: z.string()
					.transform(transformHostProofOfPossession)
					.meta({ description: "Proof of possession comprising of ${timestamp}.${keyfingerprint}.${format}:${signature}" }),
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
				certificate: z.string()
			})
				.openapi("Certificate Response")
			),
		},
		"401": {
			description: "Access to the endpoint is Unauthorized",
			...contentJson(z.object({
				status: z.literal(401),
				error: z.literal("Unauthorized")
			}))
		},
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
}
