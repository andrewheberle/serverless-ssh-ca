import { seconds } from "itty-time"
import { Certificate, createCertificate, identityForUser, identityFromDN, Key, parsePrivateKey } from "sshpk"
import { SSHExtension } from "./types"
import { env } from "cloudflare:workers"

export type CreateCertificateOptions = {
    lifetime?: number
    principals?: string[]
    extensions?: typeof env.SSH_CERTIFICATE_EXTENSIONS
}

const DefaultCreateCertificateOptions: CreateCertificateOptions = {
    lifetime: seconds(env.SSH_CERTIFICATE_LIFETIME),
    principals: [],
    extensions: env.SSH_CERTIFICATE_EXTENSIONS
}

export class CertificateExtraExtensionsError extends Error {
    constructor(message: string) {
    super(message)
    this.name = "CertificateExtraExtensionsError"

    // This is necessary for proper stack trace in TypeScript
    Object.setPrototypeOf(this, CertificateExtraExtensionsError.prototype)
  }
} 

export async function createSignedCertificate(email: string, public_key: Key, options: CreateCertificateOptions = DefaultCreateCertificateOptions): Promise<Certificate> {
    // add identities
    const identity = env.SSH_CERTIFICATE_INCLUDE_SELF
        ? [identityForUser(email.split("@")[0])]
        : []
    if (options.principals !== undefined) {
        for (const p of options.principals) {
            identity.push(identityForUser(p))
        }
    }
    for (const p of env.SSH_CERTIFICATE_PRINCIPALS) {
        identity.push(identityForUser(p))
    }

    // grab private key from secret store
    const key = parsePrivateKey(await env.PRIVATE_KEY.get())

    // lifetime is the smaller of what was provided in the options or the default
    const lifetime = options.lifetime !== undefined
        ? Math.min(options.lifetime, seconds(env.SSH_CERTIFICATE_LIFETIME))
        : seconds(env.SSH_CERTIFICATE_LIFETIME)

    // generate value for serial of certificate
    const unixTimestamp = Math.floor(Date.now() / 1000)
    const serial = Buffer.alloc(8)
    serial.writeBigUInt64BE(BigInt(unixTimestamp))

    // set issuer of certificate based on ISSUER_DN
    const issuer = identityFromDN(env.ISSUER_DN)

    // create certificate
    const certificate = createCertificate(identity, public_key, issuer, key, { lifetime: lifetime, serial: serial })

    // add usage extensions
    const extensions: SSHExtension[] = []
    if (options.extensions !== undefined) {
        // if extensions are provided in request, ensure they do not include extra extensions beyond the defaults
        for (const ext of options.extensions) {
            if (!env.SSH_CERTIFICATE_EXTENSIONS.includes(ext)) {
                throw new CertificateExtraExtensionsError(`${ext} is not allowed`)
            }

            // add to list of allowed extensions
            extensions.push({
                critical: false,
                name: ext,
                data: Buffer.alloc(0)
            })
        }
    } else {
        // use defaults if not provided
        env.SSH_CERTIFICATE_EXTENSIONS.forEach((ext: string) => {
            extensions.push({
                critical: false,
                name: ext,
                data: Buffer.alloc(0)
            })
        })

    }

    // add info to certificate
    if (certificate.signatures.openssh !== undefined) {
        certificate.signatures = {
            openssh: {
                nonce: certificate.signatures.openssh.nonce,
                keyId: email,
                signature: certificate.signatures.openssh.signature,
                exts: extensions,
            }
        }
    }

    // re-sign after changes
    certificate.signWith(key)

    return certificate
}
