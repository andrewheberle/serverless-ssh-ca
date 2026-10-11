import z from "zod"
import type { SshCaBindings } from "../../types.js"
import {
	refineRenewableCertificate,
	split,
	transformCertificate,
	transformProofOfPossession,
} from "../../utils.js"
import {
	ConflictException,
	contentJson,
	InputValidationException,
	InternalServerErrorException,
	NotFoundException,
	UnauthorizedException,
	ForbiddenException,
	UnprocessableEntityException,
} from "chanfana"
import { seconds } from "itty-time"
import { isRevoked } from "../../db/index.js"
import { CertificateType } from "../../db/types.js"
import {
	CaPublicKeyEndpointSchema,
	certificate,
	certificateTypeName,
	certificateTypeTag,
	createAccessTokenSchema,
	createIdentityTokenSchema,
	createRevocationListEndpointSchema,
	openapiStringByte,
	publicKey,
} from "../schema.js"

/**
 * The name of the header carrying the proof of possession of the private key
 */
export const ProofHeader = "Proof-Of-Possession"

export const createProofSchema = (env: SshCaBindings) => (
	z.string()
		.meta({
			description: "Proof of possession of the private key comprising of `${timestamp}.${fingerprint}.${signature}`. The signature is a BASE64 encoded armored SSHSIG signature, made with the `request-proof-of-possession@com.github.serverless-ssh-ca.andrewheberle` namespace, of `${timestamp}.${fingerprint}.${METHOD} ${path}` where `${METHOD} ${path}` is the request the proof is for, for example `DELETE /api/v4/user/certificates/12345678901234567890`. The timestamp is in milliseconds since the Unix epoch.",
			example: "1765696780805.SHA256:79mq0wtpQMTvS4+Of8VzLN0qmYWNUyTXYmqKwhEgSLs.LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K...",
		})
		.transform((val, ctx) => transformProofOfPossession(env, val, ctx))
)

/**
 * Headers for a request authorised by a proof of possession alone
 */
export const createProofHeaderSchema = (env: SshCaBindings) => (
	z.object({
		[ProofHeader]: createProofSchema(env),
	})
)

/**
 * Headers for a request authenticated with an access token and authorised by
 * a proof of possession
 */
export const createAuthenticatedHeaderSchema = (env: SshCaBindings) => (
	z.object({
		"Authorization": createAccessTokenSchema(env),
		[ProofHeader]: createProofSchema(env),
	})
)

export const serialParamSchema = z.object({
	// a string as JSON cannot carry a bigint and numbers lose precision
	// above 2^53, and without leading zeros so the path a proof is made for
	// has only one form
	serial: z.string()
		.regex(/^(0|[1-9]\d*)$/)
		.transform(BigInt)
		.refine((v) => v <= 0xFFFFFFFFFFFFFFFFn, { message: "serial must fit in an unsigned 64-bit integer" })
		.meta({ description: "Serial number of the certificate", example: "12345678901234567890" }),
})

const certificateResponse = {
	...contentJson(z.object({
		certificate: certificate,
	})
		.openapi("Certificate Response")
	)
}

export const createCaPublicKeyEndpointSchema = () => ({
	...CaPublicKeyEndpointSchema,
	operationId: "get_ca_public_key",
})

export const createGetRevocationListEndpointSchema = (certificateType: CertificateType) => ({
	...createRevocationListEndpointSchema(certificateType),
	operationId: `get_${certificateTypeName(certificateType)}_revocation_list`,
})

export const issueUserCertificateEndpointBodySchema = (env: SshCaBindings) => (
	z.object({
		public_key: publicKey,
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
		.openapi("User Certificate Issue Request")
)

export const createIssueUserCertificateEndpointSchema = (env: SshCaBindings) => ({
	tags: [certificateTypeTag(CertificateType.User)],
	operationId: "issue_user_certificate",
	summary: "Request a user certificate",
	description: `Issues a signed SSH user certificate for the provided public key. The request must be authenticated with an access token and include an identity token from the OIDC IdP for the same subject, along with a proof of possession of the private key for \`public_key\` in the \`${ProofHeader}\` header made for this request. Principals on the issued certificate are derived from the identity token.`,
	security: [{ oidcAuth: [] }],
	request: {
		headers: createAuthenticatedHeaderSchema(env),
		body: contentJson(issueUserCertificateEndpointBodySchema(env)),
	},
	responses: {
		"200": {
			description: "SSH User Certificate issued successfully",
			...certificateResponse,
		},
		...UnauthorizedException.schema(),
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
})

export const issueHostCertificateEndpointBodySchema = (env: SshCaBindings) => (
	z.object({
		public_key: publicKey,
		identity: createIdentityTokenSchema(env),
		principals: z.array(z.string()).min(1)
			.meta({ description: "List of principals to include on the issued certificate" }),
		lifetime: z.int()
			.min(seconds("24 hours"))
			.max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
			.default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
			.meta({ description: "Lifetime of issued Host SSH certificate" }),
	})
		.openapi("Host Certificate Issue Request")
)

export const createIssueHostCertificateEndpointSchema = (env: SshCaBindings) => ({
	tags: [certificateTypeTag(CertificateType.Host)],
	operationId: "issue_host_certificate",
	summary: "Request a host certificate",
	description: `Issues a signed SSH host certificate for the provided public key and principals. The request must be authenticated with an access token and include an identity token from the OIDC IdP for the same subject, along with a proof of possession of the private key for \`public_key\` in the \`${ProofHeader}\` header made for this request. The user must be permitted to request host certificates by email address or role.`,
	security: [{ oidcAuth: [] }],
	request: {
		headers: createAuthenticatedHeaderSchema(env),
		body: contentJson(issueHostCertificateEndpointBodySchema(env)),
	},
	responses: {
		"200": {
			description: "SSH Host Certificate issued successfully",
			...certificateResponse,
		},
		...UnauthorizedException.schema(),
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
})

export const renewHostCertificateEndpointBodySchema = (env: SshCaBindings) => (
	z.object({
		certificate: openapiStringByte
			.transform(transformCertificate)
			.meta({ description: "SSH certificate to renew, which must have the serial number in the path" }),
		lifetime: z.int()
			.min(seconds("24 hours"))
			.max(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
			.default(seconds(env.SSH_HOST_CERTIFICATE_LIFETIME))
			.meta({ description: "Lifetime of renewed Host SSH certificate" }),
	})
		.superRefine((val, ctx) => refineRenewableCertificate(env, isRevoked, val, ctx))
		.openapi("Host Certificate Renewal Request")
)

export const createRenewHostCertificateEndpointSchema = (env: SshCaBindings) => ({
	tags: [certificateTypeTag(CertificateType.Host)],
	operationId: "renew_host_certificate",
	summary: "Renew a host certificate",
	description: `Issues a new SSH host certificate for the same public key and principals as an existing, unexpired and unrevoked host certificate issued by this CA. No OIDC authentication is required; instead the \`${ProofHeader}\` header must contain a proof of possession of the private key for the existing certificate made for this request. The lifetime of the renewed certificate is no longer than that of the existing certificate.`,
	request: {
		params: serialParamSchema,
		headers: createProofHeaderSchema(env),
		body: contentJson(renewHostCertificateEndpointBodySchema(env)),
	},
	responses: {
		"200": {
			description: "SSH Host Certificate renewed successfully",
			...certificateResponse,
		},
		...UnauthorizedException.schema(),
		...ForbiddenException.schema(),
		...InputValidationException.schema(),
		...UnprocessableEntityException.schema(),
		...InternalServerErrorException.schema(),
	}
})

export const createRevokeCertificateEndpointSchema = (env: SshCaBindings, certificateType: CertificateType) => ({
	tags: [certificateTypeTag(certificateType)],
	operationId: `revoke_${certificateTypeName(certificateType)}_certificate`,
	summary: `Revoke a ${certificateTypeName(certificateType)} certificate`,
	description: `Revokes a ${certificateTypeName(certificateType)} certificate issued by this CA and adds it to the ${certificateTypeName(certificateType)} Key Revocation List. The \`${ProofHeader}\` header must contain a proof of possession of the private key for the public key that the certificate was issued for, made for this request. A certificate issued for a different public key is reported as not found.`,
	request: {
		params: serialParamSchema,
		headers: createProofHeaderSchema(env),
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
		...InputValidationException.schema(),
		...NotFoundException.schema(),
		...ConflictException.schema(),
		...InternalServerErrorException.schema(),
	}
})
