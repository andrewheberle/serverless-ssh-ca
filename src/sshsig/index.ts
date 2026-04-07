import { Sig } from "./sig";
import { verify as rawVerify } from "./verifier";
import { parse } from "./sig_parser";

/**
 * Verifies SSH signature against provided data.
 *
 * Returns `true` if the `signature` is a valid signature over `signed_data`, `false` otherwise.
 *
 * @param {Sig | string} signature SSH signature.
 * @param {Uint8Array | string} signed_data Data that has been signed.
 * @param {object} options Pass-in subtle crypto if required or a specific namespace.
 * @returns {Promise<boolean>} Resolves to true if the signature is valid, to false otherwise.
 */
export async function verify(
  signature: Sig | string,
  signed_data: Uint8Array | string,
  options?: {
    subtle?: SubtleCrypto;
		namespace?: string;
  },
): Promise<boolean> {
  if (typeof options === "undefined") {
    options = {};
  }
  const subtle = options.subtle || crypto.subtle;
  if (typeof signature === "string") {
    signature = parse(signature);
  }

	// check namespace matches if provided in options, otherwise default to
	// signature's namespace. Reject if they don't match.
	const namespace = options.namespace || signature.namespace;
	if (namespace !== signature.namespace) {
		return false;
	}

  if (typeof signed_data === "string") {
    signed_data = new TextEncoder().encode(signed_data);
  }
  return await rawVerify(subtle, signature, signed_data);
}
