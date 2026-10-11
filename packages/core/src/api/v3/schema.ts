import z from "zod"
import type { SshCaBindings } from "../../types.js"
import {
	split,
	refineCertificateRequest,
	transformProofOfPossession,
	transformRenewalProofOfPossession,
	refineHostCertificateRequest,
	transformCertificate,
	refineHostCertificateRenewal,
	refineRevokeCertificate,
} from "../../utils.js"
import {
	ConflictException,
	contentJson,
	ForbiddenException,
	InputValidationException,
	InternalServerErrorException,
	UnauthorizedException,
	UnprocessableEntityException,
} from "chanfana"
import { seconds } from "itty-time"
import { isRevoked } from "../../db/index.js"
import { CertificateType } from "../../db/types.js"
import {
	certificate,
	certificateTypeName,
	certificateTypeTag,
	createHeaderSchema,
	createIdentityTokenSchema,
	openapiStringByte,
	proofOfPossession,
	publicKey,
} from "../schema.js"

export {
	CaPublicKeyEndpointSchema,
	certificateTypeName,
	createAccessTokenSchema,
	createHeaderSchema,
	createIdentityTokenSchema,
	createRevocationListEndpointSchema,
} from "../schema.js"

export const userCertificateRequestEndpointBodySchema = (env: SshCaBindings) => (
	z.object({
		public_key: publicKey,
		proof: proofOfPossession
			.transform((val, ctx) => transformProofOfPossession(env, val, ctx)),
		identity: createIdentityTokenSchema(env),
		extensions: z.array(z.string())
			.default(split(env.SSH_CERTIFICATE_EXTENSIONS))
			.meta({ description: "Extensions to include in the issued SSH certificate" }),
		lifetime: z.int()
			.min(seconds("5 minutes"))
			.max(seconds(env.SSH_CERTIFICATE_LIFETIME))
			.default(seconds(env.SSH_CERTIFICATE_LIFETIME))
			.meta({ description: "Lifetime of issued SSH certificate" }),
	})
		.superRefine((val, ctx) => refineCertificateRequest(env, val, ctx))
		.openapi("User Certificate Request")
)

export const createUserCertificateRequestEndpointSchema = (env: SshCaBindings) => ({
	tags: [certificateTypeTag(CertificateType.User)],
	summary: "Request a user certificate",
	description: "Issues a signed SSH user certificate for the provided public key. The request must be authenticated with an access token and include an identity token from the OIDC IdP for the same subject, along with a proof of possession of the private key. Principals on the issued certificate are derived from the identity token.",
	security: [{ oidcAuth: [] }],
	request: {
		headers: createHeaderSchema(env),
		body: contentJson(userCertificateRequestEndpointBodySchema(env)),
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
})

export const hostCertificateRequestEndpointBodySchema = (env: SshCaBindings) => (
	z.object({
				public_key: publicKey,
				proof: proofOfPossession
					.transform((val, ctx) => transformProofOfPossession(env, val, ctx)),
				identity: createIdentityTokenSchema(env),
				principals: z.array(z.string()).min(1)
					.meta({ description: "List of principals to include on the issued certificate" }),
				lifetime: z.int()
					.min(seconds("24 hours"))
					.max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
					.default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
					.meta({ description: "Lifetime of issued Host SSH certificate" }),
			})
				.superRefine((val, ctx) => refineHostCertificateRequest(env, val, ctx))
				.openapi("Host Certificate Request")
)

export const createHostCertificateRequestEndpointSchema = (env: SshCaBindings) => ({
	tags: [certificateTypeTag(CertificateType.Host)],
	summary: "Request a host certificate",
	description: "Issues a signed SSH host certificate for the provided public key and principals. The request must be authenticated with an access token and include an identity token from the OIDC IdP for the same subject, along with a proof of possession of the private key. The user must be permitted to request host certificates by email address or role.",
	security: [{ oidcAuth: [] }],
	request: {
		headers: createHeaderSchema(env),
		body: contentJson(hostCertificateRequestEndpointBodySchema(env))
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
})

export const hostCertificateRenewEndpointBodySchema = (env: SshCaBindings) => (
	z.object({
			certificate: openapiStringByte
				.transform(transformCertificate)
				.meta({ description: "SSH certificate to renew" }),
			public_key: publicKey,
			proof: proofOfPossession
				.transform((val, ctx) => transformRenewalProofOfPossession(env, val, ctx)),
			lifetime: z.int()
				.min(seconds("24 hours"))
				.max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
				.default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
				.meta({ description: "Lifetime of renewed Host SSH certificate" }),
		})
			.superRefine((val, ctx) => refineHostCertificateRenewal(env, isRevoked, val, ctx))
			.openapi("Host Certificate Renew")
)

export const createHostCertificateRenewEndpointSchema = (env: SshCaBindings) => ({
	tags: [certificateTypeTag(CertificateType.Host)],
	summary: "Renew a host certificate",
	description: "Issues a new SSH host certificate with the same principals as an existing, unexpired and unrevoked host certificate issued by this CA. No OIDC authentication is required; instead the public key must match the existing certificate and the proof of possession must be made with its private key. The lifetime of the renewed certificate is no longer than that of the existing certificate.",
	request: {
		body: contentJson(hostCertificateRenewEndpointBodySchema(env))
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
})

export const revokeCertificateEndpointBodySchema = (env: SshCaBindings) => (
	z.object({
			// sent as a decimal string as JSON cannot carry a bigint and
			// numbers lose precision above 2^53
			serial: z.string()
				.regex(/^\d+$/)
				.transform(BigInt)
				.refine((v) => v <= 0xFFFFFFFFFFFFFFFFn, { message: "serial must fit in an unsigned 64-bit integer" })
				.meta({ description: "Serial number of certificate to revoke", example: "12345678901234567890" }),
			public_key: publicKey,
			proof: proofOfPossession
				.transform((val, ctx) => transformProofOfPossession(env, val, ctx)),
		})
			.openapi("Certificate Revocation")
			.superRefine((val, ctx) => refineRevokeCertificate(env, val, ctx))
)

export const createRevokeCertificateEndpointSchema = (env: SshCaBindings, certificateType: CertificateType) => ({
	tags: [certificateTypeTag(certificateType)],
	summary: `Revoke a ${certificateTypeName(certificateType)} certificate`,
	description: `Revokes a ${certificateTypeName(certificateType)} certificate issued by this CA, identified by its serial number, and adds it to the ${certificateTypeName(certificateType)} Key Revocation List. The request must include a proof of possession of the private key for the public key that the certificate was issued for.`,
	request: {
		body: contentJson(revokeCertificateEndpointBodySchema(env))
	},
	responses: {
		"200": {
			description: `SSH ${certificateTypeName(certificateType)} certificate revoked successfully`,
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
})
