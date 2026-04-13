import { group, Logger } from "@andrewheberle/ts-slog"
import {
	ApiException,
	ConflictException,
	ForbiddenException,
	fromHono,
	InternalServerErrorException,
	NotFoundException,
	OpenAPIRoute,
	UnauthorizedException,
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
	recordCertificate,
	RevocationStatus,
	revocationStatus,
	revokeCertificate,
} from "../../db"
import { KRLBuilder } from "../../krl"
import {
	CaPublicKeyEndpointSchema,
	HostCertificateRenewEndpointSchema,
	HostCertificateRequestEndpointSchema,
	RevocationListEndpointSchema,
	RevokeCertificateEndpointSchema,
	UserCertificateRequestEndpointSchema,
} from "./schema"

const logger = new Logger()

export const api = fromHono(new Hono())

class CaPublicKeyEndpoint extends OpenAPIRoute {
	schema = CaPublicKeyEndpointSchema

	async handle(c: AppContext) {
		const l = logger.with(
			...group("request", "action", "ca"),
		)
		try {
			const pub = await getPublic()

			return c.text(`${pub.toString("ssh").trim()}\n`)
		} catch (err) {
			switch (true) {
				case (err instanceof KeyParseError):
					l.error("error parsing private key")
					throw new InternalServerErrorException("error parsing private key")
				case (err instanceof ApiException):
					// re-throw any exisiting chanfana error
					throw err
				default:
					// otherwise throw as InternalServerErrorException
					l.error("unhandled error", "error", err)
					throw new InternalServerErrorException("internal server error")
			}
		}
	}
}
api.get("/ca", CaPublicKeyEndpoint)

class UserCertificateRequestEndpoint extends OpenAPIRoute {
	schema = UserCertificateRequestEndpointSchema

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>()

		const l = logger.with(
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
			switch (true) {
				case (err instanceof ApiException):
					// re-throw any exisiting chanfana error
					throw err
				default:
					// otherwise throw as InternalServerErrorException
					l.error("unhandled error", "error", err)
					throw new InternalServerErrorException("internal server error")
			}
		}
	}
}
api.post("/user/certificate", UserCertificateRequestEndpoint)

class RevocationListEndpoint extends OpenAPIRoute {
	schema = RevocationListEndpointSchema

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>()

		const l = logger.with(
			...group("request",
				"type", data.params.certificateType,
				"action", "krl",
			),
		)

		const certificateType = data.params.certificateType === "user" ? CertificateType.User : CertificateType.Host

		try {
			// get revoked serials
			const serials = (await getRevocationList(certificateType)).map(v => BigInt(v))

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
			switch (true) {
				case (err instanceof KeyParseError):
					l.error("error parsing private key")
					throw new InternalServerErrorException("error parsing private key")
				case (err instanceof ApiException):
					// re-throw any exisiting chanfana error
					throw err
				default:
					// otherwise throw as InternalServerErrorException
					l.error("unhandled error", "error", err)
					throw new InternalServerErrorException("internal server error")
			}
		}
	}
}
api.get("/:certificateType/krl", RevocationListEndpoint)

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
		if (!split(c.env.SSH_HOST_CERTIFICATE_ALLOWED_EMAILS).includes(data.headers.Authorization.email) && !data.body.identity.principals.some((p: string) => split(env.SSH_HOST_CERTIFICATE_ALLOWED_ROLES).includes(p))) {
			l.error("unauthorized host certificate request")
			throw new UnauthorizedException("User not allowed to issue host certificates")
		}

		const opts: CreateHostCertificateOptions = {
			lifetime: data.body.lifetime,
			principals: data.body.principals,
		}

		try {
			const certificate = await createSignedHostCertificate(data.body.public_key, opts)
			const response: CertificateSignerResponse = {
				certificate: certificate.toBuffer("openssh").toString("base64")
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
				case (err instanceof ApiException):
					// re-throw any exisiting chanfana error
					throw err
				default:
					// otherwise throw as InternalServerErrorException
					l.error("unhandled error", "error", err)
					throw new InternalServerErrorException("internal server error")
			}
		}
	}
}
api.post("/host/certificate", HostCertificateRequestEndpoint)

class HostCertificateRenewEndpoint extends OpenAPIRoute {
	schema = HostCertificateRenewEndpointSchema

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>()
		const serial = data.body.certificate.serial.readBigUInt64BE(0)

		const l = logger.with(
			...group("request",
				"type", "host",
				"action", "renewal",
				"serial", serial,
			),
		)

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
				case (err instanceof ApiException):
					// re-throw any exisiting chanfana error
					throw err
				case (err instanceof BadIssuerError):
					throw new UnprocessableEntityException(err.message)
				default:
					// otherwise throw as InternalServerErrorException
					l.error("unhandled error", "error", err)
					throw new InternalServerErrorException("internal server error")
			}
		}
	}
}
api.post("/host/renew", HostCertificateRenewEndpoint)

class RevokeCertificateEndpoint extends OpenAPIRoute {
	schema = RevokeCertificateEndpointSchema

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>()

		const l = logger.with(
			...group("request", "type", data.params.certificateType, "action", "revoke", "serial", data.body.serial),
		)

		const certificatetype = data.params.certificateType === "user" ? CertificateType.User : CertificateType.Host

		// ensure certificate can be revoked
		const status = await revocationStatus(data.body.serial, data.body.public_key.toString("ssh"), certificatetype)
		switch (status) {
			case RevocationStatus.Revoked:
				l.warn("certificate is already revoked")
				throw new ConflictException("certificate is already revoked")
			case RevocationStatus.Unrevokable:
				l.warn("cannot revoke this certificate")
				throw new ForbiddenException("cannot revoke this certificate")
			case RevocationStatus.NotFound:
				l.warn("certificate not found")
				throw new NotFoundException("certificate not found")
		}

		try {
			const res = await revokeCertificate(data.body.serial)

			if (res.length === 0) {
				throw new InternalServerErrorException("no results were returned for revocation")
			}

			if (res.length > 1) {
				logger.warn("more than one revocation result was returned", "count", res.length)
			}

			logger.info("completed revocation")
			return c.json({
				revoked_at: res[0].revoked_at
			})
		} catch (err) {
			switch (true) {
				case (err instanceof ApiException):
					// re-throw any exisiting chanfana error
					throw err
				default:
					// otherwise throw as InternalServerErrorException
					l.error("unhandled error", "error", err)
					throw new InternalServerErrorException("internal server error")
			}
		}
	}
}
api.post("/:certificateType/revoke", RevokeCertificateEndpoint)
