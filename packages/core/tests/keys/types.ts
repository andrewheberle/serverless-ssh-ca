/**
 * A key used in tests, in the formats ssh-keygen reads and writes
 */
export type TestKey = {
    /** The private key in OpenSSH format */
    privateKey: string
    /** The public key in OpenSSH format, as written by ssh-keygen -y */
    publicKey: string
}
