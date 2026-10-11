import { group } from "@andrewheberle/ts-slog"
import {
	ForbiddenException,
	fromHono,
	OpenAPIRoute,
	UnauthorizedException,
} from "chanfana"
import { Hono } from "hono"
import { AppContext } from "../../router.js"
import {
	CreateCertificateOptions,
	CreateHostCertificateOptions,
	createSignedCertificate,
	createSignedHostCertificate,
} from "../../certificate.js"
import { split } from "../../utils.js"
import { CertificateType } from "../../db/types.js"
import { caPublicKey, issueCertificate, revocationList, revoke } from "../operations.js"
import {
	CaPublicKeyEndpointSchema,
	createUserCertificateRequestEndpointSchema,
	createRevocationListEndpointSchema,
	createHostCertificateRequestEndpointSchema,
	createHostCertificateRenewEndpointSchema,
	createRevokeCertificateEndpointSchema,
	certificateTypeName,
} from "./schema.js"
import { logger } from "../../logger.js"
import type { SshCaBindings } from "../../types.js"

const CaPublicKeyEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = CaPublicKeyEndpointSchema

		override async handle(c: AppContext) {
			const l = logger(env).with(
				...group("request", "action", "ca"),
			)
			return await caPublicKey(c, l)
		}
	}
}

const UserCertificateRequestEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = createUserCertificateRequestEndpointSchema(env)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()

			const l = logger(env).with(
				...group("request",
					"type", "user",
					"action", "request",
				),
				...group("auth_token",
					"email", data.headers.Authorization.email,
					"sub", data.headers.Authorization.sub,
				),
				...group("id_token",
					"sub", data.body.identity.sub,
				),
			)

			if (data.body.identity.sub !== data.headers["Authorization"].sub) {
				l.error("token subjects did not match")
				throw new ForbiddenException("Possible token substitution as subjects for authentication and identity tokens did not match")
			}

			const opts: CreateCertificateOptions = {
				lifetime: data.body.lifetime,
				principals: data.body.identity.principals,
				extensions: data.body.extensions,
			}

			return await issueCertificate(c, l,
				() => createSignedCertificate(c.env, data.headers.Authorization.email, data.body.public_key, opts),
				CertificateType.User,
			)
		}
	}
}

const RevocationListEndpoint = (env: SshCaBindings, certificateType: CertificateType) => {
	return class extends OpenAPIRoute {
		override schema = createRevocationListEndpointSchema(certificateType)

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

const HostCertificateRequestEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = createHostCertificateRequestEndpointSchema(env)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()

			const l = logger(env).with(
				...group("request",
					"type", "host",
					"action", "request",
				),
				...group("auth_token",
					"email", data.headers.Authorization.email,
					"sub", data.headers.Authorization.sub,
				),
				...group("id_token",
					"sub", data.body.identity.sub,
				),
			)

			// check id and access token are for the same user
			if (data.body.identity.sub !== data.headers.Authorization.sub) {
				l.error("token subjects did not match")
				throw new ForbiddenException("possible token substitution as subjects for authentication and identity tokens did not match")
			}

			// check user can issue host certificates
			if (!split(c.env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS).includes(data.headers.Authorization.email) && !data.body.identity.principals.some((p: string) => split(c.env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES).includes(p))) {
				l.error("unauthorized host certificate request")
				throw new UnauthorizedException("User not allowed to issue host certificates")
			}

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

const HostCertificateRenewEndpoint = (env: SshCaBindings) => {
	return class extends OpenAPIRoute {
		override schema = createHostCertificateRenewEndpointSchema(env)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()
			const serial = data.body.certificate.serial

			const l = logger(env).with(
				...group("request",
					"type", "host",
					"action", "renewal",
					"serial", serial,
				),
			)

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
				() => createSignedHostCertificate(c.env, data.body.public_key, opts),
				CertificateType.Host,
			)
		}
	}
}

const RevokeCertificateEndpoint = (env: SshCaBindings, certificateType: CertificateType) => {
	return class extends OpenAPIRoute {
		override schema = createRevokeCertificateEndpointSchema(env, certificateType)

		override async handle(c: AppContext) {
			const data = await this.getValidatedData<typeof this.schema>()

			const l = logger(env).with(
				...group("request", "type", certificateTypeName(certificateType), "action", "revoke", "serial", data.body.serial),
			)

			return await revoke(c, l, data.body.serial, data.body.public_key, certificateType)
		}
	}
}


export const createApi = (env: SshCaBindings) => {
	const api = fromHono(new Hono())

	api.get("/ca", CaPublicKeyEndpoint(env))
	api.post("/user/certificate", UserCertificateRequestEndpoint(env))
	api.get("/user/krl", RevocationListEndpoint(env, CertificateType.User))
	api.post("/user/revoke", RevokeCertificateEndpoint(env, CertificateType.User))
	api.post("/host/certificate", HostCertificateRequestEndpoint(env))
	api.post("/host/renew", HostCertificateRenewEndpoint(env))
	api.get("/host/krl", RevocationListEndpoint(env, CertificateType.Host))
	api.post("/host/revoke", RevokeCertificateEndpoint(env, CertificateType.Host))

	return api
}
