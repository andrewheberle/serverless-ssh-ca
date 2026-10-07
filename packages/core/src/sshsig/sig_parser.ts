import { Sig } from "./sig.js";
import { Reader } from "./reader.js";
import { parsePubkey } from "./formats.js";
import { dearmor } from "./armor.js";

/**
 * ECDSA signature algorithms whose signatures need converting from SSH
 * mpint encoding to the raw r || s format used by WebCrypto.
 */
export type EcdsaSigAlgo =
  | "ecdsa-sha2-nistp256"
  | "ecdsa-sha2-nistp384"
  | "ecdsa-sha2-nistp521"
  | "sk-ecdsa-sha2-nistp256@openssh.com";

/**
 * Narrow a signature algorithm name to an {@link EcdsaSigAlgo}.
 *
 * @param sig_algo Signature algorithm name from the SSH signature.
 */
export function isEcdsaSigAlgo(sig_algo: string): sig_algo is EcdsaSigAlgo {
  return sig_algo === "ecdsa-sha2-nistp256" ||
    sig_algo === "ecdsa-sha2-nistp384" ||
    sig_algo === "ecdsa-sha2-nistp521" ||
    sig_algo === "sk-ecdsa-sha2-nistp256@openssh.com";
}

/**
 * Size in bytes of each of the r and s signature components for the curve
 * used by an {@link EcdsaSigAlgo}.
 *
 * @param sig_algo ECDSA signature algorithm name.
 */
export function ecdsaComponentSize(sig_algo: EcdsaSigAlgo): number {
  switch (sig_algo) {
    case "ecdsa-sha2-nistp256":
    case "sk-ecdsa-sha2-nistp256@openssh.com":
      return 32;
    case "ecdsa-sha2-nistp384":
      return 48;
    case "ecdsa-sha2-nistp521":
      return 66;
    default: {
      const exhaustive: never = sig_algo;
      throw new Error(`unsupported ECDSA signature algorithm: ${exhaustive}`);
    }
  }
}

/**
 * Convert an SSH mpint encoded ECDSA signature component (r or s) to a
 * fixed-width big-endian value of `size` bytes.
 *
 * Leading zero bytes are removed and the value is then left-padded with
 * zeros to `size`. This throws an Error when the value is zero or does not
 * fit in `size` bytes.
 *
 * @param mpint Component bytes as encoded in the SSH signature.
 * @param size Required width in bytes, see {@link ecdsaComponentSize}.
 */
export function toFixedWidth(mpint: Uint8Array, size: number): Uint8Array {
  let start = 0;
  while (start < mpint.length && mpint[start] === 0x00) {
    start++;
  }
  const value = mpint.subarray(start);
  if (value.length === 0 || value.length > size) {
    throw new Error("invalid ECDSA signature component");
  }
  const out = new Uint8Array(size);
  out.set(value, size - value.length);
  return out;
}

/**
 * Parse bytes into an SSH signature object.
 *
 * This function throws an Error when the signature is invalid or unsupported.
 *
 * @param {DataView | string} signature Raw bytes to parse.
 */
export function parse(signature: DataView | string): Sig {
  let view;
  if (typeof signature === "string") {
    const bytes = dearmor(signature);
    view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  } else {
    view = signature;
  }
  const reader = new Reader(view);

  const magic = reader.readBytes(6).toString();
  if (magic !== "SSHSIG") {
    throw new Error("Expected SSHSIG magic value but got unexpected bytes");
  }
  const version = reader.readUint32();
  if (version !== 1) {
    throw new Error("Expected version 1 but got unexpected version");
  }
  const raw_publickey = reader.peekString().bytes();
  const publickey = reader.readString();
  const pk_algo = publickey.readString().toString();
  const pubkey = parsePubkey(pk_algo, publickey, raw_publickey);
  const namespace = reader.readString().toString();
  const reserved = reader.readString().bytes();
  const hash_algorithm = reader.readString().toString();
  const raw_signature = reader.readString();
  const sig_algo = raw_signature.readString().toString();
  const sig_bytes = raw_signature.readString();
  let bytes;
  if (isEcdsaSigAlgo(sig_algo)) {
    // SSH encodes r and s as minimal-length mpints, but WebCrypto expects
    // the fixed-width concatenation r || s
    const size = ecdsaComponentSize(sig_algo);
    const r = toFixedWidth(new Uint8Array(sig_bytes.readString().bytes()), size);
    const s = toFixedWidth(new Uint8Array(sig_bytes.readString().bytes()), size);
    const raw = new Uint8Array(size * 2);
    raw.set(r, 0);
    raw.set(s, size);
    bytes = raw.buffer;
  } else {
    bytes = sig_bytes.bytes();
  }
  let flags, counter;
  if (
    sig_algo === "sk-ecdsa-sha2-nistp256@openssh.com" ||
    sig_algo == "sk-ssh-ed25519@openssh.com"
  ) {
    flags = new Uint8Array(raw_signature.readBytes(1).bytes())[0];
    counter = raw_signature.readUint32();
  }
  if (!reader.isAtEnd) {
    throw new Error(
      "Signature was parsed but there were still bytes in the stream.",
    );
  }
  return {
    publickey: pubkey,
    namespace,
    reserved,
    hash_algorithm,
    signature: {
      sig_algo,
      raw_signature: bytes,
      flags,
      counter,
    },
  };
}
