import type { PrivateKey } from "sshpk"
import { caKeyWireBytes, concat, encodeString, encodeUint32 } from "./krl"

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

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Sign a KRL ArrayBuffer with the CA private key and return an armored SSHSIG
 * signature string, suitable for use as the "signature" field in the KRL JSON
 * response.
 *
 * The returned string can be verified with ssh-keygen:
 *   echo -n "$KRL_BYTES" | ssh-keygen -Y verify -f allowed_signers \
 *     -I <identity> -n file -s <sig_file>
 */
export async function signKRL(
    caKey: PrivateKey,
    krl: ArrayBuffer,
): Promise<string> {
    const { cryptoKey, sigAlgo, webCryptoAlgo } = await importPrivateKey(caKey)

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
    const publicKeyWire = caKeyWireBytes(caKey)
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