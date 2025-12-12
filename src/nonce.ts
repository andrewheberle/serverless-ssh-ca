import { env } from "cloudflare:workers"
import { ms } from "itty-time"
import { Certificate, Fingerprint, FingerprintFormatError, Key, parseFingerprint, parseSignature, Signature, SignatureParseError } from "sshpk"

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

export class Nonce {
    readonly timestamp: number
    readonly fingerprint: Fingerprint
    readonly signature: Signature
    private readonly dataToVerify: string

    constructor(nonce: string) {
        const parts = nonce.split(".")
        if (parts.length !== 3) {
            throw new NonceParseError("invalid nonce format")
        }

        const [timestampStr, fingerprintHex, signatureString] = parts

        // verify timestamp
        const timestamp: number = parseInt(timestampStr, 10)
        if (isNaN(timestamp)) {
            throw new NonceParseError("timestamp was not a number")
        }

        const now = Date.now()
        const age = now - timestamp
        if (age > ms(env.CERTIFICATE_REQUEST_TIME_SKEW_MAX)) {
            throw new NonceParseError("nonce timestamp too old")
        }

        // verify fingerprint matches public key
        try {
            const fingerprint = parseFingerprint(fingerprintHex)
            if (fingerprint === undefined) {
                throw new NonceParseError("nonce fingerprint did not parse")
            }

            const signatureParts = signatureString.split(":")
            const [signatureFormat, signatureBase64] = signatureParts.length === 1 ? ["", signatureParts[0]] : signatureParts

            // parse signature
            const signature = parseSignature(signatureBase64, format(signatureFormat), "ssh")

            // set our values
            this.timestamp = timestamp
            this.fingerprint = fingerprint
            this.signature = signature
            this.dataToVerify = `${timestamp}.${fingerprintHex}`
        } catch (err) {
            switch (true) {
                case (err instanceof FingerprintFormatError):
                    throw new NonceParseError("nonce fingerprint was an invalid format", err)
                case (err instanceof SignatureParseError):
                    throw new NonceParseError("nonce signature could not be parsed", err)
                default:
                    throw err
            }
        }
    }

    /**
     * 
     * @param key public key to use to verify signature against
     * @returns true or false if verification succeeds
     */
    verify(key: Key): boolean {
        // create verifier from public key
        const verifier = key.createVerify(key.type == "ed25519" ? "sha512" : "sha256")
        verifier.update(this.dataToVerify)

        return verifier.verify(this.signature)
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