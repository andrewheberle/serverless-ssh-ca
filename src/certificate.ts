import { seconds } from "itty-time"
import { Certificate, createCertificate, identityForUser, identityFromDN, parseKey, parsePrivateKey } from "sshpk"
import { CertificateSignerPayload } from "./types"

export async function createSignedCertificate(env: Env, id: string, payload: CertificateSignerPayload, principals?: string[]): Promise<Certificate> {
    // add identities
    const identity = env.SSH_CERTIFICATE_INCLUDE_SELF
        ? [identityForUser(id)]
        : []
    if (principals !== undefined) {
        for (const p of principals) {
            identity.push(identityForUser(p))
        }
    }
    for (const p of env.SSH_CERTIFICATE_PRINCIPALS) {
        identity.push(identityForUser(p))
    }

    // grab public key from payload and private key from secret store
    const pub = parseKey(atob(payload.public_key))
    const key = parsePrivateKey(await env.PRIVATE_KEY.get())

    // lifetime is the smaller of what was provided in the payload or the default
    const lifetime = payload.lifetime !== undefined
        ? Math.min(payload.lifetime, seconds(env.SSH_CERTIFICATE_LIFETIME))
        : seconds(env.SSH_CERTIFICATE_LIFETIME)

    // generate value for serial of certificate
    const unixTimestamp = Math.floor(Date.now() / 1000)
    const serial = Buffer.alloc(8)
    serial.writeBigUInt64BE(BigInt(unixTimestamp))

    // set issuer of certificate based on ISSUER_DN
    const issuer = identityFromDN(env.ISSUER_DN)

    // create certificate
    const certificate = createCertificate(identity, pub, issuer, key, { lifetime: lifetime, serial: serial })

    // add usage extensions
    const extensions = (payload.extensions !== undefined
        ? payload.extensions
        : env.SSH_CERTIFICATE_EXTENSIONS).map((ext) => {
        return {
            critical: false,
            name: ext,
            data: Buffer.alloc(0)
        }
    })
    if (certificate.signatures.openssh !== undefined) {
        certificate.signatures = {
            openssh: {
                nonce: certificate.signatures.openssh.nonce,
                keyId: id,
                signature: certificate.signatures.openssh.signature,
                exts: extensions,
            }
        }
    }

    // re-sign after changes
    certificate.signWith(key)

    return certificate
}
