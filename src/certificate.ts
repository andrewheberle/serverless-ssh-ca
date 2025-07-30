import { seconds } from "itty-time"
import { Certificate, createCertificate, identityForUser, identityFromDN, parseKey, parsePrivateKey } from "sshpk"
import { CertificateSignerPayload } from "./types"

export async function createSignedCertificate(env: Env, id: string, payload: CertificateSignerPayload, principals?: string[]): Promise<Certificate> {
    // add identity
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
    const pub = parseKey(atob(payload.public_key))
    const issuer = identityFromDN(env.ISSUER_DN)
    const key = parsePrivateKey(await env.PRIVATE_KEY.get())
	const lifetime = payload.lifetime !== undefined
		? Math.min(payload.lifetime, seconds(env.SSH_CERTIFICATE_LIFETIME))
		: seconds(env.SSH_CERTIFICATE_LIFETIME)
    const certificate = createCertificate(identity, pub, issuer, key, { lifetime: lifetime })
    const extensions = (payload.extensions !== undefined
		? payload.extensions
		: env.SSH_CERTIFICATE_EXTENSIONS).map((ext) => {
        return {
            critical: false,
            name: ext,
            data: Buffer.alloc(0)
        }
    })

    // add usage extensions
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
