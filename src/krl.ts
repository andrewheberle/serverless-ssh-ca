import type { PrivateKey } from "sshpk"

// ── Constants ────────────────────────────────────────────────────────────────

const KRL_MAGIC = 0x5353484b524c0a00n // "SSHKRL\n\0"
const KRL_FORMAT_VERSION = 1

const KRL_SECTION_CERTIFICATES = 1
const KRL_SECTION_CERT_SERIAL_LIST = 0x20
const KRL_SECTION_CERT_KEY_ID = 0x23

// ── Low-level encoding helpers ───────────────────────────────────────────────

/** Encode a uint32 big-endian. */
export function encodeUint32(value: number): Uint8Array {
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
export function encodeString(value: Uint8Array | string): Uint8Array {
    const bytes =
        typeof value === "string" ? new TextEncoder().encode(value) : value
    const out = new Uint8Array(4 + bytes.length)
    new DataView(out.buffer).setUint32(0, bytes.length, false)
    out.set(bytes, 4)
    return out
}

/** Concatenate an arbitrary number of Uint8Arrays into one. */
export function concat(...parts: Uint8Array[]): Uint8Array {
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
export function caKeyWireBytes(caKey: PrivateKey): Uint8Array {
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

// ── KRLBuilder ───────────────────────────────────────────────────────────────

export class KRLBuilder {
    private readonly _caKey: PrivateKey
    private readonly _serials: bigint[] = []
    private readonly _keyIds: string[] = []

    constructor(caKey: PrivateKey) {
        this._caKey = caKey
    }

    /**
     * Add certificate serial numbers to be revoked.
     * May be called multiple times all serials are merged into one section.
     */
    addSerials(serials: bigint[]): this {
        this._serials.push(...serials)
        return this
    }

    /**
     * Add certificate key ID strings to be revoked.
     * May be called multiple times all key IDs are merged into one section.
     */
    addKeyIds(keyIds: string[]): this {
        this._keyIds.push(...keyIds)
        return this
    }

    /**
     * Generate the binary KRL and return it as an ArrayBuffer.
     *
     * @param krlVersion  Optional KRL version number (default: 1).
     * @param comment     Optional comment string embedded in the header.
     */
    generate(krlVersion: bigint = 1n, comment = ""): ArrayBuffer {
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
        return krl.buffer as ArrayBuffer
    }
}
