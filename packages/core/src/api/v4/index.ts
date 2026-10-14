import { group, Logger } from "@andrewheberle/ts-slog"
import {
	fromHono,
	InputValidationException,
	OpenAPIRoute,
} from "chanfana"
import { Hono } from "hono"
import type { PublicKey } from "../../ssh/keys.js"
import { AppContext } from "../../router.js"
import {
	CreateCertificateOptions,
	CreateHostCertificateOptions,
	createSignedCertificate,
	createSignedHostCertificate,
} from "../../certificate.js"
import { CertificateType } from "../../db/types.js"
import type { ProofOfPossession } from "../../proof.js"
import { authenticateRequester, caPublicKey, issueCertificate, revocationList, revoke } from "../operations.js"
import { certificateTypeName } from "../schema.js"
import {
	createCaPublicKeyEndpointSchema,
	createGetRevocationListEndpointSchema,
	createIssueHostCertificateEndpointSchema,
	createIssueUserCertificateEndpointSchema,
	createRenewHostCertificateEndpointSchema,
	createRevokeCertificateEndpointSchema,
	ProofHeader,
} from "./schema.js"
import { logger } from "../../logger.js"
import type { SshCaBindings } from "../../types.js"

/**
 * The path the v4 API is served under, which is part of the request a proof
 * of possession is made for
 */
export const BasePath = "/api/v4"

/**
 * Ensures a proof of possession was made with the private key for a public key
 * and for this request, so it cannot be replayed against another endpoint or
 * for another certificate.
 *
 * @param l The logger for the request
 * @param proof The proof of possession from the request
 * @param key The public key the proof must be made with
 * @param method The HTTP method of the request
 * @param path The path of the request below {@link BasePath}, with any parameters filled in
 * @throws {@link InputValidationException} when the proof is not valid for the key and request
 */
const verifyProof = async (l: Logger, proof: ProofOfPossession, key: PublicKey, method: string, path: string): Promise<void> => {
	if (!proof.matches(key)) {
		l.warn("proof of possession fingerprint did not match public key")
		throw new InputValidationException("proof of possession fingerprint did not match public key", ["headers", ProofHeader])
	}

	if (!await proof.verifyRequest(method, `${BasePath}${path}`)) {
		l.warn("proof of possession signature validation failed")
		throw new InputValidationException("proof of possession signature validation failed", ["headers", ProofHeader])
	}
}

const CaPublicKeyEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = createCaPublicKeyEndpointSchema()

		override async handle(c: AppContext) {
			const l = logger(env).with(
				...group("request", "action", "ca"),
			)

			return await caPublicKey(c, l)
		}
	}
}

const IssueUserCertificateEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = createIssueUserCertificateEndpointSchema(env)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()

			const { requester, l } = await authenticateRequester(c,
				logger(env).with(
					...group("request",
						"type", "user",
						"action", "request",
					),
				),
				{ authorization: data.headers.Authorization, identityToken: data.body.identity },
				CertificateType.User,
			)

			await verifyProof(l, data.headers[ProofHeader], data.body.public_key, "POST", "/user/certificates")

			const opts: CreateCertificateOptions = {
				lifetime: data.body.lifetime,
				principals: requester.principals,
				extensions: data.body.extensions,
			}

			return await issueCertificate(c, l,
				() => createSignedCertificate(c.env, requester.email, data.body.public_key, opts),
				CertificateType.User,
			)
		}
	}
}

const RevocationListEndpoint = (env: SshCaBindings, certificateType: CertificateType) => {
	return class extends OpenAPIRoute {
		override schema = createGetRevocationListEndpointSchema(certificateType)

		override async handle(c: AppContext) {
			const l = logger(env).with(
				...group("request",
					"type", certificateTypeName(certificateType),
					"action", "krl",
				),
			)

			return await revocationList(c, l, certificateType)
		}
	}
}

const IssueHostCertificateEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = createIssueHostCertificateEndpointSchema(env)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()

			const { l } = await authenticateRequester(c,
				logger(env).with(
					...group("request",
						"type", "host",
						"action", "request",
					),
				),
				{ authorization: data.headers.Authorization, identityToken: data.body.identity },
				CertificateType.Host,
			)

			await verifyProof(l, data.headers[ProofHeader], data.body.public_key, "POST", "/host/certificates")

			const opts: CreateHostCertificateOptions = {
				lifetime: data.body.lifetime,
				principals: data.body.principals,
			}

			return await issueCertificate(c, l,
				() => createSignedHostCertificate(c.env, data.body.public_key, opts),
				CertificateType.Host,
			)
		}
	}
}

const RenewHostCertificateEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = createRenewHostCertificateEndpointSchema(env)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()
			const serial = data.params.serial

			const l = logger(env).with(
				...group("request",
					"type", "host",
					"action", "renewal",
					"serial", serial,
				),
			)

			// the serial in the path is what the proof was made for, so it
			// must be the certificate being renewed
			if (data.body.certificate.serial !== serial) {
				l.warn("certificate serial did not match the serial in the path")
				throw new InputValidationException("certificate serial did not match the serial in the path", ["body", "certificate"])
			}

			await verifyProof(l, data.headers[ProofHeader], data.body.certificate.publicKey, "POST", `/host/certificates/${serial}/renew`)

			// use smaller of the current certificate lifetime and the requested lifetime
			const originalLifetime = (data.body.certificate.validBefore.getTime() - data.body.certificate.validAfter.getTime()) / 1000
			const lifetime = originalLifetime > data.body.lifetime
				? data.body.lifetime
				: originalLifetime

			const opts: CreateHostCertificateOptions = {
				lifetime: lifetime,
				principals: data.body.certificate.principals,
			}

			return await issueCertificate(c, l,
				() => createSignedHostCertificate(c.env, data.body.certificate.publicKey, opts),
				CertificateType.Host,
				data.body.certificate,
			)
		}
	}
}

const RevokeCertificateEndpoint = (env: SshCaBindings, certificateType: CertificateType) => {
	return class extends OpenAPIRoute {
		override schema = createRevokeCertificateEndpointSchema(env, certificateType)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()
			const serial = data.params.serial
			const proof = data.headers[ProofHeader]

			const l = logger(env).with(
				...group("request", "type", certificateTypeName(certificateType), "action", "revoke", "serial", serial),
			)

			// the key the proof was made with is the key the certificate must
			// have been issued for
			await verifyProof(l, proof, proof.signaturePubkey, "DELETE", `/${certificateTypeName(certificateType)}/certificates/${serial}`)

			return await revoke(c, l, serial, proof.signaturePubkey, certificateType)
		}
	}
}

export const createApi = (env: SshCaBindings) => {
	const api = fromHono(new Hono())

	api.get("/ca", CaPublicKeyEndpoint(env))
	api.post("/user/certificates", IssueUserCertificateEndpoint(env))
	api.delete("/user/certificates/:serial", RevokeCertificateEndpoint(env, CertificateType.User))
	api.get("/user/krl", RevocationListEndpoint(env, CertificateType.User))
	api.post("/host/certificates", IssueHostCertificateEndpoint(env))
	api.post("/host/certificates/:serial/renew", RenewHostCertificateEndpoint(env))
	api.delete("/host/certificates/:serial", RevokeCertificateEndpoint(env, CertificateType.Host))
	api.get("/host/krl", RevocationListEndpoint(env, CertificateType.Host))

	return api
}
