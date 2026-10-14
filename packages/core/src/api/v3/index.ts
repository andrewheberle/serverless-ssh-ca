import { group } from "@andrewheberle/ts-slog"
import {
	fromHono,
	OpenAPIRoute,
} from "chanfana"
import { Hono } from "hono"
import { AppContext } from "../../router.js"
import { issueHostCertificate, issueUserCertificate, renewHostCertificate } from "../../authority.js"
import { CertificateType } from "../../db/types.js"
import { authenticateRequester, caPublicKey, certificateResponse, revocationList, revoke } from "../operations.js"
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

			return await certificateResponse(c, l,
				issueUserCertificate(c.env, requester, data.body.public_key, { lifetime: data.body.lifetime, extensions: data.body.extensions }, l),
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

			return await certificateResponse(c, l,
				issueHostCertificate(c.env, data.body.public_key, { principals: data.body.principals, lifetime: data.body.lifetime }, l),
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

			return await certificateResponse(c, l,
				renewHostCertificate(c.env, data.body.certificate, { lifetime: data.body.lifetime }, l),
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
