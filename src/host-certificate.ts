// src/host-certificate.ts
import { 
    Certificate, 
    createCertificate, 
    identityFromDN, 
    identityForHost,
    Key, 
    parsePrivateKey,
    parseKey
} from "sshpk";
import { createHash } from "crypto"
import { seconds } from "itty-time"

/**
 * Create a signed host certificate
 */
export async function createHostCertificate(
    keyId: string,
    publicKey: Key,
    principals: string[],
    env: Env
): Promise<Certificate> {
    // Convert principals to identities
    const identities = principals.map(p => identityForHost(p));
    
    // Load CA private key
    const caKey = parsePrivateKey(await env.PRIVATE_KEY.get());
    
    // Set issuer
    const issuer = identityFromDN(env.ISSUER_DN);
    
    // Calculate lifetime (90 days in seconds)
    const lifetime = seconds(env.HOST_CERT_VALIDITY)
    
    // Generate serial number based on timestamp
    const unixTimestamp = Math.floor(Date.now() / 1000);
    const serial = Buffer.alloc(8);
    serial.writeBigUInt64BE(BigInt(unixTimestamp));
    
    // Create the certificate
    const certificate = createCertificate(
        identities,
        publicKey,
        issuer,
        caKey,
        {
            lifetime: lifetime,
            serial: serial
        }
    );
    
    // Set certificate metadata
    if (certificate.signatures.openssh !== undefined) {
        certificate.signatures = {
            openssh: {
                nonce: certificate.signatures.openssh.nonce,
                keyId: keyId,
                signature: certificate.signatures.openssh.signature,
                // Host certificates don't have extensions
                exts: []
            }
        };
    }
    
    // Re-sign after modifications
    certificate.signWith(caKey);
    
    return certificate;
}

/**
 * Verify a host certificate for renewal
 */
export async function verifyHostCertificate(
    certificate: Certificate,
    publicKey: string,
    challengeResponse: string,
    env: Env
): Promise<{ valid: boolean; reason?: string }> {
    try {
        // 1. Verify certificate signature against CA
        const caKey = parsePrivateKey(await env.PRIVATE_KEY.get());
        const caPublicKey = caKey.toPublic();
        
        if (!certificate.isSignedByKey(caPublicKey)) {
            return { valid: false, reason: "Certificate not signed by CA" };
        }
        
        // 2. Check certificate is not expired
        const now = new Date();
        if (certificate.validFrom > now || certificate.validUntil < now) {
            return { valid: false, reason: "Certificate expired or not yet valid" };
        }
        
        // 3. Verify certificate type is host certificate
        // sshpk doesn't expose the cert type directly, but we can check if it was created
        // as a host cert by checking that subjects are hosts (not users)
        // For now, we'll trust that if it was signed by our CA, it's the right type
        
        // 4. Verify public key matches certificate
        const certPublicKey = certificate.subjectKey.toString('ssh');
        const providedKey = parseKey(publicKey, 'ssh');
        const providedPublicKey = providedKey.toString('ssh');
        
        if (certPublicKey !== providedPublicKey) {
            return { valid: false, reason: "Public key does not match certificate" };
        }
        
        // 5. Verify challenge response
        const fingerprint = certificate.signatures.openssh?.keyId || providedKey.fingerprint('sha256').toString();
        const timestamp = Math.floor(Date.now() / 1000);
        
        // Try timestamps within 5 minute window
        const timeWindow = 5 * 60; // 5 minutes
        let validSignature = false;
        
        for (let offset = -timeWindow; offset <= timeWindow; offset += 1) {
            const challengeTimestamp = timestamp + offset;
            const challenge = createChallenge(fingerprint, challengeTimestamp);
            
            try {
                // Create verifier using the public key from the certificate
                const verifier = providedKey.createVerify('sha256');
                verifier.update(challenge);
                
                // Parse the signature from base64
                const responseBuffer = Buffer.from(challengeResponse, 'base64');
                
                // Verify the signature
                if (verifier.verify(responseBuffer)) {
                    validSignature = true;
                    break;
                }
            } catch (err) {
                // Continue trying other timestamps
                continue;
            }
        }
        
        if (!validSignature) {
            return { valid: false, reason: "Invalid challenge response signature" };
        }
        
        // 6. Check revocation (future - for MVP just check if env var exists)
        // TODO: Query D1 database when revocation is implemented
        
        return { valid: true };
    } catch (err) {
        console.error("Error verifying certificate:", err);
        return { valid: false, reason: "Verification error" };
    }
}

/**
 * Create a challenge for renewal authentication
 */
export function createChallenge(fingerprint: string, timestamp: number): Buffer {
    const challengeString = `host-renewal:${fingerprint}:${timestamp}`;
    return createHash('sha256').update(challengeString).digest();
}