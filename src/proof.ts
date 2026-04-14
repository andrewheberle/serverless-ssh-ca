import { env } from "cloudflare:workers"
import { ms } from "itty-time"
import { Fingerprint, FingerprintFormatError, Key, parseFingerprint, parseKey } from "sshpk"
import { verify } from "./sshsig"
import { parse } from "./sshsig/sig_parser"
import { Sig } from "./sshsig/sig"
import { group, Logger, LogLevel } from "@andrewheberle/ts-slog"

const Namespace = "proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"

export class PossessionParseError extends Error {
	constructor(message: string, cause?: unknown) {
		super(message)
		this.name = "PossessionParseError"
		this.cause = cause

		// This is necessary for proper stack trace in TypeScript
		Object.setPrototypeOf(this, PossessionParseError.prototype)
	}
}

/**
 * ProofOfPossession is used to check/enforce proof of possession for a SSH
 * private key.
 *
 * This is used to verify that the requester of a certificate actually
 * possesses the private key corresponding to the public key in the certificate
 * request.
 *
 * The proof of possession is a signed message containing a timestamp and the
 * fingerprint of the public key.
 *
 * The signature is made with the private key corresponding to the public key
 * in the certificate request and is a BASE64 encoded SSHSIG signature.
 */
export class ProofOfPossession {
	readonly timestamp: number
	readonly fingerprint: Fingerprint
	readonly signature: Sig
	readonly signaturePubkey: Key
	readonly logger: Logger
	private readonly data: string

	constructor(proof: string, options?: { from?: number, logger?: Logger }) {
		this.logger = options?.logger !== undefined ? options.logger : new Logger({ minLevel: LogLevel.None })
		const parts = proof.split(".")
		if (parts.length !== 3) {
			throw new PossessionParseError("invalid proof of possession format")
		}

		const [timestampStr, fingerprintString, signatureBase64] = parts

		// verify timestamp
		const timestamp: number = parseInt(timestampStr, 10)
		if (isNaN(timestamp)) {
			throw new PossessionParseError("timestamp was not a number")
		}

		const now = options?.from !== undefined ? options?.from : Date.now()
		const age = now - timestamp
		const skew = ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX)
		if (age > skew) {
			throw new PossessionParseError("timestamp too old")
		}
		if (age + skew < 0) {
			throw new PossessionParseError("timestamp was from the future")
		}
		try {
			// parse fingerprint
			const fingerprint = parseFingerprint(fingerprintString)
			if (fingerprint === undefined) {
				throw new PossessionParseError("fingerprint did not parse")
			}

			// convert siganture from base64
			const signature = Buffer.from(signatureBase64, "base64").toString()

			// set values
			this.timestamp = timestamp
			try {
				this.signature = parse(signature)
			} catch (err) {
				throw new PossessionParseError("proof of possession signature could not be parsed", err)
			}

			this.fingerprint = fingerprint
			this.data = `${timestamp}.${fingerprintString}`
			this.signaturePubkey = parseKey(this.signature.publickey.toString())

			// ensure the provided fingerprint matches the signature public key
			if (!this.fingerprint.matches(this.signaturePubkey)) {
				throw new PossessionParseError("proof of possession fingerprint does not match signature public key")
			}

			this.logger.debug("constructor completed",
				...group("this",
					"timestamp", this.timestamp,
					"fingerprint", this.fingerprint.toString("base64"),
					"signaturePubkey.fingerprint()", this.signaturePubkey.fingerprint().toString("base64"),
				),
			)
		} catch (err) {
			switch (true) {
				case (err instanceof FingerprintFormatError):
					throw new PossessionParseError("proof of possession fingerprint was an invalid format", err)
				default:
					throw err
			}
		}
	}

	/**
	 *
	 * @returns true if signature is valid, false otherwise
	 */
	async verify(namespace?: string): Promise<boolean> {
		return await verify(this.signature, this.data, { namespace: namespace || Namespace })
	}

	/**
	 *
	 * @param keys array of keys to verify finterprint against
	 * @returns true if the proof of possession fingerprint matches any of the provided keys, false otherwise
	 */
	matches(key: Key): boolean
	matches(...keys: Key[]): boolean

	matches(...keys: Key[]): boolean {
		this.logger.debug("matches() called", "in", "ProofOfPossession", "keys", keys.length)
		try {
			for (const key of keys) {
				// confirm proof of possession fingerprint matches keys
				this.logger.debug("this.fingerprint.matches()", "in", "ProofOfPossession", "fingerprint", this.fingerprint.toString("base64"), "key", key.toString("ssh"))
				if (!this.fingerprint.matches(key))
					return false

				// also confirm key used to sign proof of possession matches
				this.logger.debug("this.signaturePubkey.fingerprint().matches()", "in", "ProofOfPossession", "signaturePubkey", this.signaturePubkey.fingerprint().toString("base64"), "key", key.toString("ssh"))
				if (!this.signaturePubkey.fingerprint().matches(key))
					return false
			}
			this.logger.debug("matches() completed", "in", "ProofOfPossession", "keys", keys.length)
			return true
		} catch (err) {
			this.logger.error("matches() error", "in", "ProofOfPossession", "error", err)
			throw err
		}
	}
}

export class PossessionMatchError extends Error {
	constructor(message: string, cause?: unknown) {
		super(message)
		this.name = "PossessionMatchError"
		this.cause = cause

		// This is necessary for proper stack trace in TypeScript
		Object.setPrototypeOf(this, PossessionMatchError.prototype)
	}
}

export class RenewalProofOfPossession extends ProofOfPossession {
	matches(key: Key): never
	matches(...keys: Key[]): boolean

	matches(...keys: Key[]): boolean {
		this.logger.debug("matches() called", "in", "RenewalProofOfPossession", "keys", keys.length)
		if (keys.length === 1) {
			throw new PossessionMatchError("must verify both public key and certificate")
		}

		try {
			for (const key of keys) {
				this.logger.debug("this.fingerprint.matches()", "in", "RenewalProofOfPossession", "fingerprint", this.fingerprint.toString("base64"), "key", key.toString("ssh"))
				if (!this.fingerprint.matches(key))
					return false
				this.logger.debug("this.signaturePubkey.fingerprint().matches()", "in", "RenewalProofOfPossession", "signaturePubkey", this.signaturePubkey.fingerprint().toString("base64"), "key", key.toString("ssh"))
				if (!this.signaturePubkey.fingerprint().matches(key))
					return false
			}
			this.logger.debug("matches() completed", "in", "RenewalProofOfPossession", "keys", keys.length)
			return true
		} catch (err) {
			this.logger.error("error in matches()", "in", "RenewalProofOfPossession", "error", err)
			throw err
		}
	}
}
