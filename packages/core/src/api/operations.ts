import { group, Logger } from "@andrewheberle/ts-slog"
import {
	ApiException,
	ConflictException,
	InputValidationException,
	InternalServerErrorException,
	NotFoundException,
	UnprocessableEntityException,
} from "chanfana"
import type { AppContext } from "../router.js"
import type { CertificateSignerResponse } from "../types.js"
import { BadIssuerError, CertificateError } from "../certificate.js"
import type { SshCertificate } from "../ssh/certificate.js"
import { KeyParseError, type PublicKey } from "../ssh/keys.js"
import { getPrivateKey, getPublic, UnsupportedKeyError } from "../utils.js"
import { CertificateType } from "../db/types.js"
import { KRLBuilder } from "../krl.js"
import {
	getKrlVersion,
	getRevocationList,
	recordCertificate,
	recordRenewal,
	RevocationStatus,
	revocationStatus,
	revokeCertificate,
} from "../db/index.js"

/**
 * Maps an error from an operation that uses the CA key to an API error.
 */
const caKeyError = (l: Logger, err: unknown): ApiException => {
	switch (true) {
		case (err instanceof UnsupportedKeyError):
			l.error(err.message)
			return new InternalServerErrorException(err.message)
		case (err instanceof KeyParseError):
			l.error("error parsing private key")
			return new InternalServerErrorException("error parsing private key")
		case (err instanceof ApiException):
			// re-throw any exisiting chanfana error
			return err
		default:
			// otherwise throw as InternalServerErrorException
			l.error("unhandled error", "error", err)
			return new InternalServerErrorException("internal server error")
	}
}

/**
 * Returns the public key of the CA in OpenSSH format.
 *
 * @param c The request context
 * @param l The logger for the request
 * @returns The response containing the CA public key
 */
export const caPublicKey = async (c: AppContext, l: Logger): Promise<Response> => {
	try {
		const pub = await getPublic(c.env)

		return c.text(`${pub.toString()}\n`)
	} catch (err) {
		throw caKeyError(l, err)
	}
}

/**
 * Returns the signed Key Revocation List for a type of certificate.
 *
 * @param c The request context
 * @param l The logger for the request
 * @param certificateType The type of certificate to return the KRL for
 * @returns The response containing the KRL and its signature
 */
export const revocationList = async (c: AppContext, l: Logger, certificateType: CertificateType): Promise<Response> => {
	try {
		// get revoked serials
		const serials = (await getRevocationList(c.env, certificateType)).map(v => BigInt(v))

		// grab private key from secret store
		const key = await getPrivateKey(c.env)

		// generate KRL
		const krl = new KRLBuilder(key)
			.addSerials(serials)

		// the version only changes when the content of the KRL does
		const version = await getKrlVersion(c.env, certificateType, await krl.digest())

		const krlBytes = krl.generate(version)

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
		throw caKeyError(l, err)
	}
}

/**
 * Signs a certificate, records it so it can later be revoked and returns it
 * as the response to a certificate request or renewal.
 *
 * These are the steps shared by every API version once a request has been
 * validated and authorised.
 *
 * @param c The request context
 * @param l The logger for the request
 * @param sign Signs and returns the certificate
 * @param certificateType The type of certificate being issued
 * @param renews The host certificate being renewed, which is revoked when the new certificate is recorded
 * @returns The response containing the issued certificate
 */
export const issueCertificate = async (c: AppContext, l: Logger, sign: () => Promise<SshCertificate>, certificateType: CertificateType, renews?: SshCertificate): Promise<Response> => {
	try {
		const certificate = await sign()
		const response: CertificateSignerResponse = {
			certificate: btoa(certificate.toString())
		}

		let recorded: boolean
		try {
			if (renews === undefined) {
				await recordCertificate(c.env, certificate, certificate.keyId, certificateType)
				recorded = true
			} else {
				recorded = await recordRenewal(c.env, renews, certificate)
			}
		} catch (err) {
			// a certificate that is not recorded cannot be revoked, so do not issue it
			l.error("there was a problem adding issued certificate to database", "error", err)
			throw new InternalServerErrorException("there was a problem recording the issued certificate")
		}

		if (!recorded) {
			// the certificate was revoked, or renewed by another request, since it was checked
			l.warn("certificate presented for renewal was revoked before the renewal was recorded")
			throw new InputValidationException("the provided certificate is revoked", ["body", "certificate"])
		}

		l.info("completed issuing certificate",
			...group(
				"certificate", "principals",
				certificate.principals.join(","), "serial", certificate.serial,
			),
			...(renews === undefined ? [] : group("renewed", "serial", renews.serial)),
		)

		return c.json(response)
	} catch (err) {
		switch (true) {
			case (err instanceof UnsupportedKeyError):
				l.error(err.message)
				throw new InternalServerErrorException(err.message)
			case (err instanceof ApiException):
				// re-throw any exisiting chanfana error
				throw err
			case (err instanceof BadIssuerError):
				throw new UnprocessableEntityException(err.message)
			case (err instanceof CertificateError):
				// the request was valid but asked for a certificate the CA's
				// configuration does not allow, such as an extension that is
				// not permitted or one without any principals
				l.warn("certificate could not be issued", "error", err.message)
				throw new UnprocessableEntityException(err.message)
			default:
				// otherwise throw as InternalServerErrorException
				l.error("unhandled error", "error", err)
				throw new InternalServerErrorException("internal server error")
		}
	}
}

/**
 * Revokes a certificate once the requester has proven possession of the
 * private key for the public key it was issued for.
 *
 * @param c The request context
 * @param l The logger for the request
 * @param serial The serial of the certificate to revoke
 * @param publicKey The public key the requester has proven possession of
 * @param certificateType The type of certificate being revoked
 * @returns The response containing the time of revocation
 */
export const revoke = async (c: AppContext, l: Logger, serial: bigint, publicKey: PublicKey, certificateType: CertificateType): Promise<Response> => {
	// ensure certificate can be revoked
	const status = await revocationStatus(c.env, serial, publicKey, certificateType)
	switch (status) {
		case RevocationStatus.Revoked:
			l.warn("certificate is already revoked")
			throw new ConflictException("certificate is already revoked")
		case RevocationStatus.NotFound:
			l.warn("certificate not found")
			throw new NotFoundException("certificate not found")
	}

	try {
		const res = await revokeCertificate(c.env, serial)

		if (res.length === 0) {
			// another request revoked the certificate after its status was checked
			l.warn("certificate was revoked by another request")
			throw new ConflictException("certificate is already revoked")
		}

		if (res.length > 1) {
			l.warn("more than one revocation result was returned", "count", res.length)
		}

		l.info("completed revocation")
		return c.json({
			revoked_at: res[0]!.revoked_at
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
