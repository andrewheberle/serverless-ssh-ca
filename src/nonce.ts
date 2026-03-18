import { env } from "cloudflare:workers"
import { ms } from "itty-time"
import { Fingerprint, FingerprintFormatError, Key, parseFingerprint, parseKey, parseSignature, Signature, SignatureParseError } from "sshpk"
import { verify } from "./sshsig"
import { parse } from "./sshsig/sig_parser"
import { Sig } from "./sshsig/sig"

export class NonceParseError extends Error {
    constructor(message: string, cause?: unknown) {
        super(message)
        this.name = "NonceParseError"
        this.cause = cause

        // This is necessary for proper stack trace in TypeScript
        Object.setPrototypeOf(this, NonceParseError.prototype)
    }
}

export class NonceMatchesError extends Error {
    constructor(message: string, cause?: unknown) {
        super(message)
        this.name = "NonceMatchesError"
        this.cause = cause

        // This is necessary for proper stack trace in TypeScript
        Object.setPrototypeOf(this, NonceMatchesError.prototype)
    }
}

export class Nonce {
    readonly timestamp: number
    readonly fingerprint: Fingerprint
    readonly signature: Sig
    private readonly signaturePubkey: Key
    private readonly data: string

    constructor(nonce: string, from?: number) {
        const parts = nonce.split(".")
        if (parts.length !== 3) {
            throw new NonceParseError("invalid nonce format")
        }

        const [timestampStr, fingerprintHex, signatureBase64] = parts

        // verify timestamp
        const timestamp: number = parseInt(timestampStr, 10)
        if (isNaN(timestamp)) {
            throw new NonceParseError("timestamp was not a number")
        }

        const now = from !== undefined ? from : Date.now()
        const age = now - timestamp
        const skew = ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX)
        if (age > skew) {
            throw new NonceParseError("nonce timestamp too old")
        }
        if (age + skew < 0) {
            throw new NonceParseError("nonce timestamp was from the future")
        }
        try {
            // parse fingerprint
            const fingerprint = parseFingerprint(fingerprintHex)
            if (fingerprint === undefined) {
                throw new NonceParseError("nonce fingerprint did not parse")
            }

            // convert siganture from base64
            const signature = atob(signatureBase64)

            // set values
            this.timestamp = timestamp
            try {
                this.signature = parse(signature)
            } catch (err) {
                throw new NonceParseError("nonce signature could not be parsed", err)
            }
            this.fingerprint = fingerprint
            this.data = `${timestamp}.${fingerprintHex}`
            this.signaturePubkey = parseKey(this.signature.publickey.toString())
        } catch (err) {
            switch (true) {
                case (err instanceof FingerprintFormatError):
                    throw new NonceParseError("nonce fingerprint was an invalid format", err)
                case (err instanceof DOMException):
                    if (err.name == "InvalidCharacterError") {
                        throw new NonceParseError("nonce signature could not be parsed", err)
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
     * @param key key to verify fingerprint against
     * @returns
     */
    matches(key: Key): boolean {
        return this.fingerprint.matches(key)
    }
}

export class HostNonce extends Nonce {
    /**
     * 
     * @param keys keys to verify fingerprint against
     * @returns
     */
    matches(...keys: Key[]): boolean {
        if (keys.length === 0) {
            throw new NonceMatchesError("host nonce must match against one or more keys")
        }

        for (const key of keys) {
            if (!this.fingerprint.matches(key))
                return false
        }

        return true
    }
}
