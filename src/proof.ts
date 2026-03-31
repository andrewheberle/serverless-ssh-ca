import { env } from "cloudflare:workers"
import { ms } from "itty-time"
import { Fingerprint, FingerprintFormatError, Key, parseFingerprint, parseKey } from "sshpk"
import { verify } from "./sshsig"
import { parse } from "./sshsig/sig_parser"
import { Sig } from "./sshsig/sig"

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
 * ProofOfPossession is used to check/enforce proof of possession for a SSH private key.
 *
 * This is used to verify that the requester of a certificate actually possesses the private key corresponding to the public key in the certificate request.
 *
 * The proof of possession is a signed message containing a timestamp and the fingerprint of the public key.
 *
 * The signature is made with the private key corresponding to the public key in the certificate request and is a BASE64 encoded SSHSIG signature.
 */
export class ProofOfPossession {
    readonly timestamp: number
    readonly fingerprint: Fingerprint
    readonly signature: Sig
    private readonly signaturePubkey: Key
    private readonly data: string

    constructor(nonce: string, from?: number) {
        const parts = nonce.split(".")
        if (parts.length !== 3) {
            throw new PossessionParseError("invalid proof of possession format")
        }

        const [timestampStr, fingerprintHex, signatureBase64] = parts

        // verify timestamp
        const timestamp: number = parseInt(timestampStr, 10)
        if (isNaN(timestamp)) {
            throw new PossessionParseError("timestamp was not a number")
        }

        const now = from !== undefined ? from : Date.now()
        const age = now - timestamp
        const skew = ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX)
        if (age > skew) {
            throw new PossessionParseError("proof of possession timestamp too old")
        }
        if (age + skew < 0) {
            throw new PossessionParseError("proof of possession timestamp was from the future")
        }
        try {
            // parse fingerprint
            const fingerprint = parseFingerprint(fingerprintHex)
            if (fingerprint === undefined) {
                throw new PossessionParseError("proof of possession	 fingerprint did not parse")
            }

            // convert siganture from base64
            const signature = atob(signatureBase64)

            // set values
            this.timestamp = timestamp
            try {
                this.signature = parse(signature)
            } catch (err) {
                throw new PossessionParseError("proof of possession signature could not be parsed", err)
            }
            this.fingerprint = fingerprint
            this.data = `${timestamp}.${fingerprintHex}`
            this.signaturePubkey = parseKey(this.signature.publickey.toString())
        } catch (err) {
            switch (true) {
                case (err instanceof FingerprintFormatError):
                    throw new PossessionParseError("proof of possession fingerprint was an invalid format", err)
                case (err instanceof DOMException):
                    if (err.name == "InvalidCharacterError") {
                        throw new PossessionParseError("proof of possession signature could not be parsed", err)
                    }
                default:
                    throw err
            }
        }
    }

    /**
     *
     * @returns
     */
    async verify(): Promise<boolean> {
        try {
            return await verify(this.signature, this.data)
        } catch (err) {
            return false
        }
    }

    /**
     *
     * @param keys array of keys to verify finterprint against
     * @returns
     */
    matches(key: Key): boolean
    matches(...keys: Key[]): boolean

    matches(...keys: Key[]): boolean {
        if (keys.length === 1) {
            return this.fingerprint.matches(keys[0])
        }

        for (const key of keys) {
            // confirm nonce fingerprint matches keys
            if (!this.fingerprint.matches(key))
                return false

            // also config key used to sign nonce matches
            if (!this.signaturePubkey.fingerprint().matches(key))
                return false
        }

        return true
    }
}

export class HostProofOfPossession extends ProofOfPossession {
    matches(...keys: Key[]): boolean {
        if (keys.length === 1) {
            // must verify key and cert
            return false
        }

        for (const key of keys) {
            if (!this.fingerprint.matches(key))
                return false
        }

        return true
    }
}
