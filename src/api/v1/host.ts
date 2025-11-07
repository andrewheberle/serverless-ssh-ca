// src/api/v1/host.ts
import { IRequest, IttyRouter, StatusError, json } from "itty-router";
import { CFArgs } from "../../router";
import { parseKey, parseCertificate } from "sshpk";
import { createHostCertificate, verifyHostCertificate } from "../../host-certificate";
import { 
    DeviceCodeResponse, 
    DeviceCodeTokenRequest, 
    HostInfoSubmission, 
    HostCertificateRequest,
    HostCertificateRenewalRequest,
    HostCertificateResponse,
    DeviceFlowState 
} from "../../host-types";
import { withHostAdminJWT } from "../../host-verify";

export const router = IttyRouter<IRequest, CFArgs>({ base: '/api/v1/host' })

// Generate a random device code
function generateDeviceCode(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Generate a user-friendly code (XXXX-XXXX format)
function generateUserCode(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude ambiguous chars
    let code = '';
    const array = new Uint8Array(8);
    crypto.getRandomValues(array);
    
    for (let i = 0; i < 8; i++) {
        code += chars[array[i] % chars.length];
        if (i === 3) code += '-';
    }
    return code;
}

// Get host fingerprint from public key
function getHostFingerprint(publicKey: string): string {
    const key = parseKey(publicKey, 'ssh');
    return key.fingerprint('sha256').toString();
}

router
    // Initiate device code flow
    .post("/device/code", async (request, env, ctx) => {
        try {
            const deviceCode = generateDeviceCode();
            const userCode = generateUserCode();
            const expiresIn = 900; // 15 minutes
            const expirationTimestamp = Math.floor(Date.now() / 1000) + expiresIn;
            
            const state: DeviceFlowState = {
                user_code: userCode,
                status: "pending",
                created_at: Math.floor(Date.now() / 1000),
                host_info: null,
                admin_email: null,
                approved_at: null
            };
            
            // Store in KV with TTL and expiration metadata
            await env.DEVICE_CODES.put(`device:${deviceCode}`, JSON.stringify(state), {
                expirationTtl: expiresIn,
                metadata: { expiration: expirationTimestamp }
            });
            
            // Store reverse lookup
            await env.DEVICE_CODES.put(`usercode:${userCode}`, deviceCode, {
                expirationTtl: expiresIn,
                metadata: { expiration: expirationTimestamp }
            });
            
            const response: DeviceCodeResponse = {
                device_code: deviceCode,
                user_code: userCode,
                verification_uri: `${new URL(request.url).origin}/device`,
                verification_uri_complete: `${new URL(request.url).origin}/device?user_code=${userCode}`,
                expires_in: expiresIn,
                interval: 5
            };
            
            return response;
        } catch (err) {
            console.error("Error generating device code:", err);
            throw new StatusError(500);
        }
    })
    
    // Poll for authorization
    .post("/device/token", async (request, env, ctx) => {
        try {
            const body = await request.json<DeviceCodeTokenRequest>();
            
            if (!body.device_code) {
                throw new StatusError(400, "Missing device_code");
            }
            
            const stateJson = await env.DEVICE_CODES.get(`device:${body.device_code}`);
            if (!stateJson) {
                return json({ error: "expired_token" }, { status: 400 });
            }
            
            const state: DeviceFlowState = JSON.parse(stateJson);
            
            switch (state.status) {
                case "pending":
                    return json({ error: "authorization_pending" }, { status: 400 });
                case "awaiting_host_info":
                    return json({ status: "awaiting_host_info" });
                case "awaiting_approval":
                    return json({ status: "awaiting_approval" });
                case "approved":
                    return json({ status: "approved" });
                case "denied":
                    return json({ error: "access_denied" }, { status: 403 });
                default:
                    return json({ error: "invalid_grant" }, { status: 400 });
            }
        } catch (err) {
            if (err instanceof StatusError) throw err;
            console.error("Error polling device token:", err);
            throw new StatusError(500);
        }
    })
    
    // Submit host information
    .post("/device/submit", async (request, env, ctx) => {
        try {
            const body = await request.json<HostInfoSubmission>();
            
            if (!body.device_code || !body.public_key || !body.hostname || !body.ip_addresses) {
                throw new StatusError(400, "Missing required fields");
            }
            
            const stateWithMetadata = await env.DEVICE_CODES.getWithMetadata(`device:${body.device_code}`);
            if (!stateWithMetadata.value) {
                throw new StatusError(404, "Device code not found or expired");
            }
            
            const state: DeviceFlowState = JSON.parse(stateWithMetadata.value);
            
            // Can only submit if admin has authenticated
            if (state.status !== "pending" && state.status !== "awaiting_host_info") {
                throw new StatusError(400, "Invalid state for host info submission");
            }
            
            // Validate public key format
            try {
                parseKey(body.public_key, 'ssh');
            } catch {
                throw new StatusError(400, "Invalid SSH public key format");
            }
            
            // Build principals list
            const principals = [
                body.hostname,
                ...body.ip_addresses,
                ...(body.additional_principals || [])
            ];
            
            // Get fingerprint
            const fingerprint = getHostFingerprint(body.public_key);
            
            // Update state
            state.host_info = {
                public_key: body.public_key,
                fingerprint: fingerprint,
                hostname: body.hostname,
                ip_addresses: body.ip_addresses,
                additional_principals: body.additional_principals || [],
                principals: principals
            };
            state.status = "awaiting_approval";
            
            // Calculate remaining TTL from metadata
            const expirationTimestamp = (stateWithMetadata.metadata as { expiration?: number })?.expiration;
            const now = Math.floor(Date.now() / 1000);
            const remainingTtl = expirationTimestamp ? Math.max(0, expirationTimestamp - now) : 900;
            
            await env.DEVICE_CODES.put(`device:${body.device_code}`, JSON.stringify(state), {
                expirationTtl: remainingTtl,
                metadata: { expiration: expirationTimestamp }
            });
            
            return json({
                status: "submitted",
                message: "Host information submitted. Awaiting administrator approval."
            });
        } catch (err) {
            if (err instanceof StatusError) throw err;
            console.error("Error submitting host info:", err);
            throw new StatusError(500);
        }
    })
    
    // Issue initial host certificate
    .post("/certificate", async (request, env, ctx) => {
        try {
            const body = await request.json<HostCertificateRequest>();
            
            if (!body.device_code || !body.public_key) {
                throw new StatusError(400, "Missing required fields");
            }
            
            const stateJson = await env.DEVICE_CODES.get(`device:${body.device_code}`);
            if (!stateJson) {
                throw new StatusError(404, "Device code not found or expired");
            }
            
            const state: DeviceFlowState = JSON.parse(stateJson);
            
            if (state.status !== "approved" || !state.host_info) {
                throw new StatusError(403, "Device not approved or missing host info");
            }
            
            // Verify public key matches
            if (state.host_info.public_key !== body.public_key) {
                throw new StatusError(400, "Public key mismatch");
            }
            
            // Parse the public key
            const publicKey = parseKey(body.public_key, 'ssh');
            
            // Create and sign certificate
            const certificate = await createHostCertificate(
                state.host_info.fingerprint,
                publicKey,
                state.host_info.principals,
                env
            );
            
            const response: HostCertificateResponse = {
                certificate: certificate.toString('openssh'),
                principals: state.host_info.principals,
                valid_after: certificate.validFrom.getTime() / 1000,
                valid_before: certificate.validUntil.getTime() / 1000,
                key_id: state.host_info.fingerprint
            };
            
            console.log(`Issued host certificate for ${state.host_info.hostname} (${state.host_info.fingerprint})`);
            
            return response;
        } catch (err) {
            if (err instanceof StatusError) throw err;
            console.error("Error issuing host certificate:", err);
            throw new StatusError(500);
        }
    })
    
    // Renew host certificate
    .post("/certificate/renew", async (request, env, ctx) => {
        try {
            const body = await request.json<HostCertificateRenewalRequest>();
            
            if (!body.current_certificate || !body.public_key || !body.challenge_response) {
                throw new StatusError(400, "Missing required fields");
            }
            
            // Parse and verify the current certificate
            const currentCert = parseCertificate(body.current_certificate, 'openssh');
            if (!('signatures' in currentCert)) {
                throw new StatusError(400, "Invalid certificate format");
            }
            
            const certificate = currentCert
            
            // Verify certificate
            const verification = await verifyHostCertificate(certificate, body.public_key, body.challenge_response, env);
            
            if (!verification.valid) {
                throw new StatusError(403, verification.reason || "Certificate verification failed");
            }
            
            // Extract principals from current certificate
            const principals = certificate.subjects.map(s => s.hostname || s.toString());
            
            // Extract fingerprint (key_id)
            const fingerprint = certificate.signatures.openssh?.keyId || getHostFingerprint(body.public_key);
            
            // Create new certificate with same principals
            const publicKey = parseKey(body.public_key, 'ssh');
            const newCertificate = await createHostCertificate(
                fingerprint,
                publicKey,
                principals,
                env
            );
            
            const response: HostCertificateResponse = {
                certificate: newCertificate.toString('openssh'),
                principals: principals,
                valid_after: newCertificate.validFrom.getTime() / 1000,
                valid_before: newCertificate.validUntil.getTime() / 1000,
                key_id: fingerprint
            };
            
            console.log(`Renewed host certificate for ${fingerprint}`);
            
            return response;
        } catch (err) {
            if (err instanceof StatusError) throw err;
            console.error("Error renewing host certificate:", err);
            throw new StatusError(500);
        }
    });