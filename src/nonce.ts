import { env } from "cloudflare:workers"
import { ms } from "itty-time"
import { Fingerprint, FingerprintFormatError, Key, parseFingerprint, parseSignature, Signature, SignatureParseError } from "sshpk"
import { verify } from "./sshsig"
import { parse } from "./sshsig/sig_parser"
import { Sig } from "./sshsig/sig"

// try to parse as ecdsa, ed25519 then rsa
const parsesignature = (s: string): Signature => {
    try {
        // try ecdsa
        return parseSignature(s, "ecdsa", "ssh")
    } catch (err) {
        if (err instanceof SignatureParseError) {
            try {
                // try ed25519
                return parseSignature(s, "ed25519", "ssh")
            } catch (err) {
                if (err instanceof SignatureParseError) {
                    try {
                        // try rsa
                        return parseSignature(s, "rsa", "ssh")
                    } catch (err) {
                        // just throw here as we are out of options
                        throw err
                    }
                } else {
                    throw err
                }
            }
        } else {
            throw err
        }
    }
}


export class NonceParseError extends Error {
    constructor(message: string, cause?: unknown) {
        super(message)
        this.name = "NonceParseError"
        this.cause = cause

        // This is necessary for proper stack trace in TypeScript
        Object.setPrototypeOf(this, NonceParseError.prototype)
    }
}

const format = (s: string): "ecdsa" | "ed25519" | "rsa" => {
    switch (s) {
        case "ecdsa-sha2-nistp25":
            return "ecdsa"
        case "ssh-ed25519":
            return "ed25519"
        case "ssh-rsa":
            return "rsa"
        default:
            // default to this to support older clients
            return "ecdsa"
    }
}

function base64ToBuffer(base64: string): Buffer<ArrayBufferLike> {
    return Buffer.from(base64, "base64")
}


export class Nonce {
    readonly timestamp: number
    readonly fingerprint: Fingerprint
    readonly signature: Sig
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
        if (age > ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX)) {
            throw new NonceParseError("nonce timestamp too old")
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
            if (!this.fingerprint.matches(key))
                return false
        }

        return true
    }
}

export class HostNonce extends Nonce {
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
