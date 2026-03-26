import type { PrivateKey } from "sshpk"

// ── Constants ────────────────────────────────────────────────────────────────

const KRL_MAGIC = 0x5353484b524c0a00n // "SSHKRL\n\0"
const KRL_FORMAT_VERSION = 1

const KRL_SECTION_CERTIFICATES = 1
const KRL_SECTION_CERT_SERIAL_LIST = 0x20
const KRL_SECTION_CERT_KEY_ID = 0x23

// ── Low-level encoding helpers ───────────────────────────────────────────────

/** Encode a uint32 big-endian. */
function encodeUint32(value: number): Uint8Array {
    const buf = new Uint8Array(4)
    new DataView(buf.buffer).setUint32(0, value, false)
    return buf
}

/** Encode a uint64 big-endian from a bigint. */
function encodeUint64(value: bigint): Uint8Array {
    const buf = new Uint8Array(8)
    new DataView(buf.buffer).setBigUint64(0, value, false)
    return buf
}

/**
 * Encode an SSH "string" (RFC 4251 §5): uint32 length followed by raw bytes.
 * Accepts either a Uint8Array (raw bytes) or a JS string (encoded as UTF-8).
 */
function encodeString(value: Uint8Array | string): Uint8Array {
    const bytes =
        typeof value === "string" ? new TextEncoder().encode(value) : value
    const out = new Uint8Array(4 + bytes.length)
    new DataView(out.buffer).setUint32(0, bytes.length, false)
    out.set(bytes, 4)
    return out
}

/** Concatenate an arbitrary number of Uint8Arrays into one. */
function concat(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((n, p) => n + p.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

/**
 * Wrap bytes as a KRL section: byte section_type + string section_data.
 * The spec defines each section as:  byte type  |  string data
 */
function encodeSection(sectionType: number, data: Uint8Array): Uint8Array {
    return concat(new Uint8Array([sectionType]), encodeString(data))
}

// ── CA public-key extraction ─────────────────────────────────────────────────

/**
 * Extract the SSH wire-format public key bytes from an sshpk PrivateKey.
 *
 * sshpk's "ssh" format produces a string like:
 *   ssh-ed25519 AAAA...base64... [comment]
 *
 * The base64 blob *is* the SSH wire encoding of the public key, so we just
 * decode it.  This works for both Ed25519 and ECDSA keys.
 */
function caKeyWireBytes(caKey: PrivateKey): Uint8Array {
    const sshString = caKey.toPublic().toString("ssh")
    // Format: "<type> <base64> [<comment>]"  — we want the second token.
    const base64 = sshString.trim().split(/\s+/)[1]
    if (!base64) {
        throw new Error("Unexpected sshpk 'ssh' format output: " + sshString)
    }
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }
    return bytes
}

// ── Constants ────────────────────────────────────────────────────────────────

const SSHSIG_MAGIC = new TextEncoder().encode("SSHSIG")
const SIG_VERSION = 1
const NAMESPACE = "file"
const HASH_ALGORITHM = "sha512"

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * PEM string → raw DER bytes (strips header/footer and decodes base64).
 * Works for both PKCS8 ("-----BEGIN PRIVATE KEY-----") and any other PEM type.
 */
function pemToDer(pem: string): Uint8Array {
    const lines = pem
        .trim()
        .split("\n")
        .filter((l) => !l.startsWith("-----"))
    const binary = atob(lines.join(""))
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }
    return bytes
}

/**
 * Import an sshpk PrivateKey into a WebCrypto CryptoKey.
 * Supports Ed25519 and ECDSA (P-256 / P-384 / P-521).
 */
async function importPrivateKey(caKey: PrivateKey): Promise<{
    cryptoKey: CryptoKey
    sigAlgo: string // SSH signature algorithm name
    webCryptoAlgo: SubtleCryptoSignAlgorithm
}> {
    const pkcs8Pem = caKey.toString("pkcs8")
    const der = pemToDer(pkcs8Pem)
    const type = caKey.type // "ed25519" | "ecdsa" | etc.
    const curve = (caKey as unknown as { curve?: string }).curve

    if (type === "ed25519") {
        const cryptoKey = await crypto.subtle.importKey(
            "pkcs8",
            der,
            { name: "Ed25519" },
            false,
            ["sign"],
        )
        return {
            cryptoKey,
            sigAlgo: "ssh-ed25519",
            webCryptoAlgo: { name: "Ed25519" },
        }
    } else if (type === "ecdsa") {
        let namedCurve: string
        let sigAlgo: string
        let hash: string

        if (curve === "nistp256") {
            namedCurve = "P-256"
            sigAlgo = "ecdsa-sha2-nistp256"
            hash = "SHA-256"
        } else if (curve === "nistp384") {
            namedCurve = "P-384"
            sigAlgo = "ecdsa-sha2-nistp384"
            hash = "SHA-384"
        } else if (curve === "nistp521") {
            namedCurve = "P-521"
            sigAlgo = "ecdsa-sha2-nistp521"
            hash = "SHA-512"
        } else {
            throw new Error(`Unsupported ECDSA curve: ${curve}`)
        }

        const cryptoKey = await crypto.subtle.importKey(
            "pkcs8",
            der,
            { name: "ECDSA", namedCurve },
            false,
            ["sign"],
        )
        return {
            cryptoKey,
            sigAlgo,
            webCryptoAlgo: { name: "ECDSA", hash: { name: hash } },
        }
    } else {
        throw new Error(`Unsupported key type: ${type}`)
    }
}

/**
 * Convert a WebCrypto ECDSA signature (IEEE P1363: raw r||s) to the SSH wire
 * encoding: string(algo) + string(mpint(r) + mpint(s)).
 *
 * SSH mpints are big-endian, with a leading 0x00 byte if the high bit is set.
 */
function p1363ToSshEcdsaSig(
    p1363: Uint8Array,
    sigAlgo: string,
): Uint8Array {
    const half = p1363.length / 2
    const r = p1363.slice(0, half)
    const s = p1363.slice(half)

    function encodeMpint(n: Uint8Array): Uint8Array {
        // Strip leading zero bytes, then re-pad if high bit set.
        let start = 0
        while (start < n.length - 1 && n[start] === 0) start++
        const trimmed = n.slice(start)
        const padded =
            trimmed[0] & 0x80 ? concat(new Uint8Array([0x00]), trimmed) : trimmed
        return encodeString(padded)
    }

    const innerSig = concat(encodeMpint(r), encodeMpint(s))
    return concat(encodeString(sigAlgo), encodeString(innerSig))
}

/**
 * Wrap an Ed25519 WebCrypto signature into SSH wire encoding:
 * string(algo) + string(sig_bytes)
 */
function wrapEd25519Sig(sig: Uint8Array): Uint8Array {
    return concat(encodeString("ssh-ed25519"), encodeString(sig))
}

/**
 * Base64-encode bytes and wrap in SSH signature armor at 76 chars per line.
 */
function armorSignature(bytes: Uint8Array): string {
    let b64 = btoa(String.fromCharCode(...bytes))
    const lines: string[] = []
    for (let i = 0; i < b64.length; i += 76) {
        lines.push(b64.slice(i, i + 76))
    }
    return [
        "-----BEGIN SSH SIGNATURE-----",
        ...lines,
        "-----END SSH SIGNATURE-----",
    ].join("\n")
}

// ── KRLBuilder ───────────────────────────────────────────────────────────────

export class KRLBuilder {
    private readonly _caKey: PrivateKey
    private readonly _serials: bigint[] = []
    private readonly _keyIds: string[] = []
    private _krl: ArrayBuffer | null = null

    constructor(caKey: PrivateKey) {
        this._caKey = caKey
    }

    /**
     * Add certificate serial numbers to be revoked.
     * May be called multiple times all serials are merged into one section.
     * 
     * This must not be called after generate() has been called
     */
    addSerials(serials: bigint[]): this {
        if (this._krl !== null) { 
            throw new Error("addSerials cannot be called after KRL has been generated")
        } 
        this._serials.push(...serials)
        return this
    }

    /**
     * Add certificate key ID strings to be revoked.
     * May be called multiple times all key IDs are merged into one section.
     * 
     * This must not be called after generate() has been called
     */
    addKeyIds(keyIds: string[]): this {
        if (this._krl !== null) { 
            throw new Error("addKeyIds cannot be called after KRL has been generated")
        }
        this._keyIds.push(...keyIds)
        return this
    }

    /**
     * Generate the binary KRL
     *
     * @param krlVersion  Optional KRL version number (default: 1).
     * @param comment     Optional comment string embedded in the header.
     */
    generate(krlVersion: bigint = 1n, comment = ""): ArrayBuffer {
        if (this._krl !== null) {
            return this._krl
        }

        // ── Header ──────────────────────────────────────────────────────────────
        const generatedDate = BigInt(Math.floor(Date.now() / 1000))

        const header = concat(
            encodeUint64(KRL_MAGIC),
            encodeUint32(KRL_FORMAT_VERSION),
            encodeUint64(krlVersion),
            encodeUint64(generatedDate),
            encodeUint64(0n), // flags — none defined
            encodeString(""), // reserved
            encodeString(comment)
        )

        // ── Certificate sub-sections ─────────────────────────────────────────────

        const certSubSections: Uint8Array[] = []

        // KRL_SECTION_CERT_SERIAL_LIST
        if (this._serials.length > 0) {
            const serialBytes = concat(...this._serials.map(encodeUint64))
            certSubSections.push(
                encodeSection(KRL_SECTION_CERT_SERIAL_LIST, serialBytes)
            )
        }

        // KRL_SECTION_CERT_KEY_ID
        if (this._keyIds.length > 0) {
            const keyIdBytes = concat(
                ...this._keyIds.map((id) => encodeString(id))
            )
            certSubSections.push(
                encodeSection(KRL_SECTION_CERT_KEY_ID, keyIdBytes)
            )
        }

        // ── KRL_SECTION_CERTIFICATES wrapper ────────────────────────────────────
        //
        // Format (inside the outer section's string data):
        //   string  ca_key
        //   string  reserved
        //   <one or more cert sub-sections>
        //
        const certSectionData = concat(
            encodeString(caKeyWireBytes(this._caKey)), // ca_key
            encodeString(""), // reserved
            ...certSubSections
        )

        const certificatesSection = encodeSection(
            KRL_SECTION_CERTIFICATES,
            certSectionData
        )

        // ── Assemble final KRL ───────────────────────────────────────────────────
        const krl = concat(header, certificatesSection)

        this._krl = krl.buffer as ArrayBuffer

        return this._krl
    }

    /**
     * Return the SSHSIG signature of the KRL.
     * 
     * This must be called after generate()
     *
     * The returned string can be verified with ssh-keygen:
     *   echo -n "$KRL_BYTES" | ssh-keygen -Y verify -f allowed_signers \
     *     -I <identity> -n file -s <sig_file>
     */
    async signature(): Promise<string> {
        let krl: ArrayBuffer
        if (this._krl === null) {
            krl = this.generate()
        } else {
            krl = this._krl
        }
        const { cryptoKey, sigAlgo, webCryptoAlgo } = await importPrivateKey(this._caKey)
    
        // 1. Hash the KRL bytes with SHA-512.
        const krlHash = new Uint8Array(
            await crypto.subtle.digest("SHA-512", krl),
        )
    
        // 2. Build the signed data blob.
        //
        //   byte[6]  "SSHSIG"
        //   string   namespace
        //   string   reserved  (empty)
        //   string   hash_algorithm
        //   string   H(message)
        const signedData = concat(
            SSHSIG_MAGIC,
            encodeString(NAMESPACE),
            encodeString(""),      // reserved
            encodeString(HASH_ALGORITHM),
            encodeString(krlHash),
        )
    
        // 3. Sign the blob.
        const rawSig = new Uint8Array(
            await crypto.subtle.sign(webCryptoAlgo, cryptoKey, signedData),
        )
    
        // 4. Encode the signature into SSH wire format.
        const sshSig =
            sigAlgo === "ssh-ed25519"
                ? wrapEd25519Sig(rawSig)
                : p1363ToSshEcdsaSig(rawSig, sigAlgo)
    
        // 5. Assemble the outer SSHSIG blob.
        //
        //   byte[6]  "SSHSIG"
        //   uint32   SIG_VERSION (1)
        //   string   publickey
        //   string   namespace
        //   string   reserved  (empty)
        //   string   hash_algorithm
        //   string   signature
        const publicKeyWire = caKeyWireBytes(this._caKey)
        const sigBlob = concat(
            SSHSIG_MAGIC,
            encodeUint32(SIG_VERSION),
            encodeString(publicKeyWire),
            encodeString(NAMESPACE),
            encodeString(""),      // reserved
            encodeString(HASH_ALGORITHM),
            encodeString(sshSig),
        )
    
        // 6. Armor and return.
        return armorSignature(sigBlob)
    }
}
