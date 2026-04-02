import { group, Logger } from "@andrewheberle/ts-slog"
import {
	ForbiddenException,
	fromHono,
	InternalServerErrorException,
	OpenAPIRoute,
	UnprocessableEntityException,
} from "chanfana"
import { Hono } from "hono"
import { AppContext } from "../../router"
import { env } from "cloudflare:workers"
import { CertificateSignerResponse } from "../../types"
import {
	BadIssuerError,
	CreateCertificateOptions,
	CreateHostCertificateOptions,
	createSignedCertificate,
	createSignedHostCertificate,
} from "../../certificate"
import {
	getPublic,
	parseIdentity,
	split,
} from "../../utils"
import {
	KeyParseError,
	parsePrivateKey,
} from "sshpk"
import {
	CertificateType,
	getRevocationList,
	isRevoked,
	recordCertificate,
} from "../../db"
import { KRLBuilder } from "../../krl"
import {
	CaPublicKeyEndpointSchema,
	HostCertificateRenewEndpointSchema,
	HostCertificateRequestEndpointSchema,
	RevocationListEndpointSchema,
	UserCertificateRequestEndpointSchema,
} from "./schema"

const logger = new Logger()

export const api = fromHono(new Hono())

class CaPublicKeyEndpoint extends OpenAPIRoute {
	schema = CaPublicKeyEndpointSchema

	async handle(c: AppContext) {
		try {
			const pub = await getPublic()

			return c.text(`${pub}\n`)
		} catch (err) {
			if (err instanceof KeyParseError) {
				throw new InternalServerErrorException("Error parsing private key")
			}

			// otherwise throw as InternalServerErrorException
			throw new InternalServerErrorException(`${err}`)
		}
	}
}
api.get("/ca", CaPublicKeyEndpoint)

class UserCertificateRequestEndpoint extends OpenAPIRoute {
	schema = UserCertificateRequestEndpointSchema

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>()

		const l = logger.with(
			...group("request", "type", "user", "action", "request"),
			...group("auth_token", "email", data.headers.Authorization.email, "sub", data.headers.Authorization.sub),
		)

		const identity = await parseIdentity(data.body.identity, c.env.JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM)
		if (identity.sub !== data.headers["Authorization"].sub) {
			l.error("token subjects did not match",
				...group("id_token",
					"sub", identity.sub,
				),
			)
			throw new ForbiddenException("Possible token substitution as subjects for authentication and identity tokens did not match")
		}

		const opts: CreateCertificateOptions = {
			lifetime: data.body.lifetime,
			principals: identity.principals,
			extensions: data.body.extensions,
		}

		try {
			const certificate = await createSignedCertificate(data.headers.Authorization.email, data.body.public_key, opts)
			const response: CertificateSignerResponse = {
				certificate: btoa(certificate.toString("openssh"))
			}

			try {
				await recordCertificate(certificate, data.headers.Authorization.email)
			} catch (err) {
				l.error("there was a problem adding issued certificate to database", "error", err)
			}

			l.info("completed issuing certificate",
				...group(
					"certificate", "principals",
					certificate.subjects.map(v => v.toString()).join(","), "serial", certificate.serial.readBigUInt64BE(0),
				),
			)

			return c.json(response)
		} catch (err) {
			// otherwise throw as InternalServerErrorException
			throw new InternalServerErrorException(`${err}`)
		}
	}
}
api.post("/user/certificate", UserCertificateRequestEndpoint)

class UserRevocationListEndpoint extends OpenAPIRoute {
	certificateType: CertificateType = CertificateType.User
	schema = RevocationListEndpointSchema

	async handle(c: AppContext) {
		try {
			// get revoked serials
			const serials = (await getRevocationList(this.certificateType)).map(v => BigInt(v))

			// grab private key from secret store
			const secret = await c.env.PRIVATE_KEY.get()

			// parse key
			const key = parsePrivateKey(secret)

			// generate KRL
			const krl = new KRLBuilder(key)
				.addSerials(serials)

			const krlBytes = krl.generate()

			// convert to base64
			const bytes = new Uint8Array(krlBytes)
			let binary = ""
			for (const byte of bytes) {
				binary += String.fromCharCode(byte)
			}
			const base64Krl = btoa(binary)

			const signature = await krl.signature()

			return c.json({
				krl: base64Krl,
				signature: signature,
			})
		} catch (err) {
			logger.error("krl error", "error", err)
			// otherwise throw as InternalServerErrorException
			throw new InternalServerErrorException(`${err}`)
		}
	}
}

api.get("/user/krl", UserRevocationListEndpoint)

class HostCertificateRequestEndpoint extends OpenAPIRoute {
	schema = HostCertificateRequestEndpointSchema

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>()

		const l = logger.with(
			...group("request",
				"type", "host",
				"action", "request",
			),
			...group("auth_token",
				"email", data.headers.Authorization.email,
				"sub", data.headers.Authorization.sub,
			),
		)

		const identity = await parseIdentity(data.body.identity, c.env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES_CLAIM)
		if (identity.sub !== data.headers.Authorization.sub) {
			l.error("token subjects did not match",
				...group("id_token",
					"sub", identity.sub,
				),
			)
			throw new ForbiddenException("Possible token substitution as subjects for authentication and identity tokens did not match")
		}

		// check user can issue host certificates
		if (!split(c.env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS).includes(data.headers.Authorization.email) && !identity.principals.some((p: string) => split(env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES).includes(p))) {
			l.error("unauthorized host certificate request")
			throw new ForbiddenException("User not allowed to issue host certificates")
		}

		const opts: CreateHostCertificateOptions = {
			lifetime: data.body.lifetime,
			principals: data.body.principals,
		}

		try {
			const certificate = await createSignedHostCertificate(data.body.public_key, opts)
			const response: CertificateSignerResponse = {
				certificate: btoa(certificate.toString("openssh"))
			}

			try {
				await recordCertificate(certificate, `host_${certificate.subjects[0].hostname}`, CertificateType.Host)
			} catch (err) {
				l.error("there was a problem adding issued certificate to database", "error", err)
			}

			l.info("completed issuing certificate",
				...group(
					"certificate", "principals",
					certificate.subjects.map(v => v.toString()).join(","), "serial", certificate.serial.readBigUInt64BE(0),
				),
			)

			return c.json(response)
		} catch (err) {
			switch (true) {
				case (err instanceof DOMException):
					if (err.name === "InvalidCharacterError") {
						throw new UnprocessableEntityException("The content was not valid base64 encoded data")
					}
			}

			// otherwise throw as InternalServerErrorException
			throw new InternalServerErrorException(`${err}`)
		}
	}
}
api.post("/host/certificate", HostCertificateRequestEndpoint)

class HostRevocationListEndpoint extends UserRevocationListEndpoint {
	certificateType: CertificateType = CertificateType.Host
}
api.get("/host/krl", HostRevocationListEndpoint)

class HostCertificateRenewEndpoint extends OpenAPIRoute {
	schema = HostCertificateRenewEndpointSchema

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>()
		const serial = data.body.certificate.serial.readBigUInt64BE(0)

		const l = logger.with(
			...group("request", "type", "host", "action", "renewal", "serial", serial),
		)

		// ensure certificate presented for renewal process is not revoked

		if (await isRevoked(serial)) {
			l.error("attempt to renew using revoked certificate")
			throw new ForbiddenException("current certificate is revoked")
		}

		// use smaller of the current certificate lifetime and the requested lifetime
		const originalLifetime = (data.body.certificate.validUntil.getTime() - data.body.certificate.validFrom.getTime()) / 1000
		const lifetime = originalLifetime > data.body.lifetime
			? data.body.lifetime
			: originalLifetime

		const opts: CreateHostCertificateOptions = {
			lifetime: lifetime,
			subjects: data.body.certificate.subjects
		}

		try {
			const certificate = await createSignedHostCertificate(data.body.public_key, opts)
			const response: CertificateSignerResponse = {
				certificate: btoa(certificate.toString("openssh"))
			}

			try {
				await recordCertificate(certificate, `host_${certificate.subjects[0].hostname}`, CertificateType.Host)
			} catch (err) {
				l.error("there was a problem adding issued certificate to database", "error", err)
			}

			l.info("completed issuing certificate",
				...group(
					"certificate", "principals",
					certificate.subjects.map(v => v.toString()).join(","), "serial", certificate.serial.readBigUInt64BE(0),
				),
			)

			return c.json(response)
		} catch (err) {
			switch (true) {
				case (err instanceof DOMException):
					if (err.name === "InvalidCharacterError") {
						throw new UnprocessableEntityException("The content was not valid base64 encoded data")
					}
				case (err instanceof BadIssuerError):
					throw new UnprocessableEntityException(err.message)
			}

			// otherwise throw as InternalServerErrorException
			throw new InternalServerErrorException(`${err}`)
		}
	}
}
api.post("/host/renew", HostCertificateRenewEndpoint)
