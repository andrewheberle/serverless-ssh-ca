// src/device-ui.ts
import { IRequest, IttyRouter, StatusError, html } from "itty-router";
import { CFArgs } from "./router";
import { DeviceFlowState } from "./host-types";
import { withHostAdminJWT } from "./host-verify";

export const router = IttyRouter<IRequest, CFArgs>({ base: '/device' })

router
    // Device authorization page
    .get("/", async (request, env, ctx) => {
        const url = new URL(request.url);
        const userCode = url.searchParams.get("user_code");
        
        if (!userCode) {
            return html(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Device Authorization</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
                        .error { color: #d32f2f; padding: 16px; background: #ffebee; border-radius: 4px; }
                        input { font-size: 18px; padding: 12px; width: 200px; text-transform: uppercase; letter-spacing: 2px; }
                        button { font-size: 18px; padding: 12px 24px; background: #1976d2; color: white; border: none; border-radius: 4px; cursor: pointer; }
                        button:hover { background: #1565c0; }
                    </style>
                </head>
                <body>
                    <h1>Device Authorization</h1>
                    <p>Enter the code displayed on your device:</p>
                    <form method="get">
                        <input type="text" name="user_code" placeholder="XXXX-XXXX" required pattern="[A-Z0-9]{4}-[A-Z0-9]{4}" maxlength="9">
                        <button type="submit">Continue</button>
                    </form>
                </body>
                </html>
            `);
        }
        
        // Check if user code exists
        const deviceCode = await env.DEVICE_CODES.get(`usercode:${userCode}`);
        if (!deviceCode) {
            return html(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Device Authorization</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
                        .error { color: #d32f2f; padding: 16px; background: #ffebee; border-radius: 4px; margin-bottom: 20px; }
                        a { color: #1976d2; }
                    </style>
                </head>
                <body>
                    <div class="error">
                        <strong>Error:</strong> Invalid or expired code
                    </div>
                    <p><a href="/device">Try again</a></p>
                </body>
                </html>
            `, { status: 404 });
        }
        
        // Redirect to OIDC for authentication
        const state = encodeURIComponent(JSON.stringify({ user_code: userCode }));
        const callbackUrl = `${url.origin}/device/callback`;
        
        // Build OIDC authorization URL
        const authUrl = new URL(env.JWT_ISSUER + '/authorize'); // Adjust based on your IdP
        authUrl.searchParams.set('client_id', env.OIDC_CLIENT_ID);
        authUrl.searchParams.set('redirect_uri', callbackUrl);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'openid email profile groups');
        authUrl.searchParams.set('state', state);
        
        return Response.redirect(authUrl.toString(), 302);
    })
    
    // OIDC callback
    .get("/callback", async (request, env, ctx) => {
        // This is a placeholder - you'll need to implement OIDC callback handling
        // similar to your client-side implementation
        const url = new URL(request.url);
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        
        if (!code || !state) {
            throw new StatusError(400, "Missing code or state");
        }
        
        try {
            const stateData = JSON.parse(decodeURIComponent(state));
            const userCode = stateData.user_code;
            
            // Exchange code for token
            // NOTE: This requires implementing OIDC token exchange
            // For now, we'll skip to the approval page and require manual JWT
            
            return Response.redirect(`/device/approve?user_code=${userCode}`, 302);
        } catch (err) {
            console.error("Error in OIDC callback:", err);
            throw new StatusError(500);
        }
    })
    
    // Approval page (with JWT verification)
    .get("/approve", withHostAdminJWT, async (request, env, ctx) => {
        const url = new URL(request.url);
        const userCode = url.searchParams.get("user_code");
        
        if (!userCode) {
            throw new StatusError(400, "Missing user_code");
        }
        
        const deviceCode = await env.DEVICE_CODES.get(`usercode:${userCode}`);
        if (!deviceCode) {
            throw new StatusError(404, "Invalid or expired code");
        }
        
        const stateWithMetadata = await env.DEVICE_CODES.getWithMetadata(`device:${deviceCode}`);
        if (!stateWithMetadata.value) {
            throw new StatusError(404, "Device session expired");
        }
        
        const state: DeviceFlowState = JSON.parse(stateWithMetadata.value);
        
        // Update state with admin info if still pending
        if (state.status === "pending") {
            state.status = "awaiting_host_info";
            state.admin_email = request.email;
            
            const expirationTimestamp = (stateWithMetadata.metadata as { expiration?: number })?.expiration;
            const now = Math.floor(Date.now() / 1000);
            const remainingTtl = expirationTimestamp ? Math.max(0, expirationTimestamp - now) : 900;
            
            await env.DEVICE_CODES.put(`device:${deviceCode}`, JSON.stringify(state), {
                expirationTtl: remainingTtl,
                metadata: { expiration: expirationTimestamp }
            });
        }
        
        // Show status page
        if (state.host_info === null) {
            return html(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Device Authorization</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <meta http-equiv="refresh" content="5">
                    <style>
                        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
                        .status { color: #2e7d32; padding: 16px; background: #e8f5e9; border-radius: 4px; margin-bottom: 20px; }
                        .waiting { color: #f57c00; padding: 16px; background: #fff3e0; border-radius: 4px; margin-bottom: 20px; }
                        .info { color: #0277bd; padding: 16px; background: #e1f5fe; border-radius: 4px; margin-top: 20px; }
                    </style>
                </head>
                <body>
                    <h1>Device Authorization</h1>
                    <div class="status">
                        ✓ Authenticated as ${request.email}
                    </div>
                    <div class="waiting">
                        Waiting for host to submit information...
                    </div>
                    <div class="info">
                        <strong>MVP Note:</strong> This page will refresh automatically every 5 seconds.
                        In the future, this will update in real-time.
                    </div>
                </body>
                </html>
            `);
        }
        
        // Show approval form with host info
        return html(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Device Authorization</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
                    .status { color: #2e7d32; padding: 16px; background: #e8f5e9; border-radius: 4px; margin-bottom: 20px; }
                    .principals { background: #f5f5f5; padding: 16px; border-radius: 4px; margin: 20px 0; }
                    .principals ul { list-style: none; padding: 0; }
                    .principals li { padding: 8px; margin: 4px 0; background: white; border-radius: 4px; }
                    .principal-type { color: #666; font-size: 14px; margin-left: 8px; }
                    .fingerprint { font-family: monospace; font-size: 14px; word-break: break-all; }
                    .buttons { margin-top: 24px; }
                    button { font-size: 16px; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; margin-right: 12px; }
                    .approve { background: #2e7d32; color: white; }
                    .approve:hover { background: #1b5e20; }
                    .deny { background: #d32f2f; color: white; }
                    .deny:hover { background: #c62828; }
                </style>
            </head>
            <body>
                <h1>Device Authorization</h1>
                <div class="status">
                    ✓ Authenticated as ${request.email}<br>
                    ✓ Host Information Received
                </div>
                
                <h2>Review Certificate Principals</h2>
                <p>The following principals will be added to the host certificate:</p>
                
                <div class="principals">
                    <ul>
                        <li><strong>${state.host_info.hostname}</strong> <span class="principal-type">(hostname)</span></li>
                        ${state.host_info.ip_addresses.map(ip => 
                            `<li><strong>${ip}</strong> <span class="principal-type">(IP address)</span></li>`
                        ).join('')}
                        ${state.host_info.additional_principals.map(p => 
                            `<li><strong>${p}</strong> <span class="principal-type">(additional)</span></li>`
                        ).join('')}
                    </ul>
                </div>
                
                <p><strong>Public Key Fingerprint:</strong></p>
                <div class="fingerprint">${state.host_info.fingerprint}</div>
                
                <form method="post" action="/device/approve">
                    <input type="hidden" name="user_code" value="${userCode}">
                    <input type="hidden" name="action" value="approve">
                    <div class="buttons">
                        <button type="submit" class="approve">Approve</button>
                        <button type="submit" class="deny" onclick="this.form.action.value='deny'">Deny</button>
                    </div>
                </form>
            </body>
            </html>
        `);
    })
    
    // Handle approval/denial
    .post("/approve", withHostAdminJWT, async (request, env, ctx) => {
        const formData = await request.formData();
        const userCode = formData.get("user_code") as string;
        const action = formData.get("action") as string;
        
        if (!userCode) {
            throw new StatusError(400, "Missing user_code");
        }
        
        const deviceCode = await env.DEVICE_CODES.get(`usercode:${userCode}`);
        if (!deviceCode) {
            throw new StatusError(404, "Invalid or expired code");
        }
        
        const stateWithMetadata = await env.DEVICE_CODES.getWithMetadata(`device:${deviceCode}`);
        if (!stateWithMetadata.value) {
            throw new StatusError(404, "Device session expired");
        }
        
        const state: DeviceFlowState = JSON.parse(stateWithMetadata.value);
        
        if (action === "approve") {
            state.status = "approved";
            state.approved_at = Math.floor(Date.now() / 1000);
        } else {
            state.status = "denied";
        }
        
        const expirationTimestamp = (stateWithMetadata.metadata as { expiration?: number })?.expiration;
        const now = Math.floor(Date.now() / 1000);
        const remainingTtl = expirationTimestamp ? Math.max(0, expirationTimestamp - now) : 900;
        
        await env.DEVICE_CODES.put(`device:${deviceCode}`, JSON.stringify(state), {
            expirationTtl: remainingTtl,
            metadata: { expiration: expirationTimestamp }
        });
        
        if (action === "approve") {
            return html(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Device Authorization</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
                        .success { color: #2e7d32; padding: 16px; background: #e8f5e9; border-radius: 4px; }
                    </style>
                </head>
                <body>
                    <div class="success">
                        <h2>✓ Device Approved Successfully</h2>
                        <p>The host certificate can now be issued.</p>
                        <p>You may close this window.</p>
                    </div>
                </body>
                </html>
            `);
        } else {
            return html(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Device Authorization</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; }
                        .error { color: #d32f2f; padding: 16px; background: #ffebee; border-radius: 4px; }
                    </style>
                </head>
                <body>
                    <div class="error">
                        <h2>Device Authorization Denied</h2>
                        <p>The device enrollment has been denied.</p>
                        <p>You may close this window.</p>
                    </div>
                </body>
                </html>
            `);
        }
    })