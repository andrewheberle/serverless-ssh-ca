import { parsePrivateKey, PublicKey, type PrivateKey } from "../../src/ssh/keys.js"
import type { TestKey } from "../keys/types.js"

/**
 * Returns the public key of a test key as used by the CA
 */
export const pub = (key: TestKey): PublicKey => PublicKey.parse(key.publicKey)

/**
 * Returns a test key as a CA private key
 */
export const priv = (key: TestKey): Promise<PrivateKey> => parsePrivateKey(key.privateKey)
