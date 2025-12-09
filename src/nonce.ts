import { env } from "cloudflare:workers"
import { ms } from "itty-time"
import { Certificate, Fingerprint, FingerprintFormatError, Key, parseFingerprint, parseSignature, Signature, SignatureParseError } from "sshpk"

export class NonceParseError extends Error {
    constructor(message: string, cause?: unknown) {
        super(message)
        this.name = "NonceParseError"
        this.cause = cause

        // This is necessary for proper stack trace in TypeScript
        Object.setPrototypeOf(this, NonceParseError.prototype)
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

        const [timestampStr, fingerprintHex, signatureBase64] = parts

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

            // parse signature
            const signature = parseSignature(signatureBase64, "ecdsa", "ssh")

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
     * @param key public key to use to verify fingerprint and signature against
     * @returns true or false if verification succeeds
     */
    verify(key: Key) {
        // create verifier from public key
        const verifier = key.createVerify("sha256")
        verifier.update(this.dataToVerify)

        return verifier.verify(this.signature)
    }

    matches(key: Key): boolean {
        return this.fingerprint.matches(key)
    }
}


export class HostNonce {
    readonly timestamp: number
    readonly fingerprint: Fingerprint
    readonly certificateFingerprint: Fingerprint
    readonly signature: Signature
    private readonly dataToVerify: string

    constructor(nonce: string) {
        const parts = nonce.split(".")
        if (parts.length !== 4) {
            throw new NonceParseError("invalid nonce format")
        }

        const [timestampStr, fingerprintHex, certificateFingerprintHex, signatureBase64] = parts

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

            const certificateFingerprint = parseFingerprint(certificateFingerprintHex)
            if (fingerprint === undefined) {
                throw new NonceParseError("nonce certificate fingerprint did not parse")
            }

            // parse signature
            const signature = parseSignature(signatureBase64, "ecdsa", "ssh")

            // set our values
            this.timestamp = timestamp
            this.fingerprint = fingerprint
            this.certificateFingerprint = certificateFingerprint
            this.signature = signature
            this.dataToVerify = `${timestamp}.${fingerprintHex}.${certificateFingerprintHex}`
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
     * @param key public key to use to verify fingerprint and signature against
     * @returns true or false if verification succeeds
     */
    verify(key: Key): boolean {
        // create verifier from public key
        const verifier = key.createVerify("sha256")
        verifier.update(this.dataToVerify)

        return verifier.verify(this.signature)
    }

    matches(key: Key): boolean
    matches(certificate: Certificate): boolean
    matches(v: Key | Certificate): boolean {
        if (Key.isKey(v, [1, 7])) {
            return this.fingerprint.matches(v)
        }

        if (Certificate.isCertificate(v, [1, 1])) {
            return this.certificateFingerprint.matches(v)
        }

        return false
    }

}