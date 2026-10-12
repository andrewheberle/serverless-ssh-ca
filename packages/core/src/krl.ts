import type { PrivateKey } from "./ssh/keys.js"
import { createSigner } from "./ssh/signer.js"

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
function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
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

// ── Constants ────────────────────────────────────────────────────────────────

const SSHSIG_MAGIC = new TextEncoder().encode("SSHSIG")
const SIG_VERSION = 1
const NAMESPACE = "krl@com.github.serverless-ssh-ca.andrewheberle"
const HASH_ALGORITHM = "sha512"

/**
 * Base64-encode bytes and wrap in SSH signature armor at 76 chars per line.
 */
function armorSignature(bytes: Uint8Array): string {
    const b64 = btoa(String.fromCharCode(...bytes))
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
     * Return a hex encoded SHA-256 digest of the content of the KRL.
     *
     * The digest covers the CA public key and the revoked serials and key IDs,
     * but not the order they were added in or the header, so it only changes
     * when the set of revoked certificates or the CA does.
     */
    async digest(): Promise<string> {
        const serials = [...this._serials].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        const keyIds = [...this._keyIds].sort()

        const content = concat(
            encodeString(this._caKey.publicKey.blob),
            encodeUint32(serials.length),
            ...serials.map(encodeUint64),
            encodeUint32(keyIds.length),
            ...keyIds.map((id) => encodeString(id)),
        )

        const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", content))
        return Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("")
    }

    /**
     * Generate the binary KRL
     *
     * @param krlVersion  Optional KRL version number (default: 1).
     * @param comment     Optional comment string embedded in the header.
     * @param generatedAt Optional time the KRL was generated (default: now).
     */
    generate(krlVersion: bigint = 1n, comment = "", generatedAt?: Date): ArrayBuffer {
        if (this._krl !== null) {
            return this._krl
        }

        // ── Header ──────────────────────────────────────────────────────────────
        const generatedDate = BigInt(Math.floor((generatedAt?.getTime() ?? Date.now()) / 1000))

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
            encodeString(this._caKey.publicKey.blob), // ca_key
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
        const signer = await createSigner(this._caKey)

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

        // 3. Sign the blob, which returns the signature in SSH wire format.
        const sshSig = await signer.sign(signedData)

        // 4. Assemble the outer SSHSIG blob.
        //
        //   byte[6]  "SSHSIG"
        //   uint32   SIG_VERSION (1)
        //   string   publickey
        //   string   namespace
        //   string   reserved  (empty)
        //   string   hash_algorithm
        //   string   signature
        const sigBlob = concat(
            SSHSIG_MAGIC,
            encodeUint32(SIG_VERSION),
            encodeString(signer.publicKey),
            encodeString(NAMESPACE),
            encodeString(""),      // reserved
            encodeString(HASH_ALGORITHM),
            encodeString(sshSig),
        )

        // 5. Armor and return.
        return armorSignature(sigBlob)
    }
}
