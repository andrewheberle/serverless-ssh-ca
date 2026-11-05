# Authenticate admins with an identity-aware proxy

Admins are authenticated by an identity-aware proxy in front of `/admin` (such as Cloudflare Access), not by a login flow in the CA. The CA verifies the signed JWT the proxy adds to each request, against a configured header, JWKS URL, issuer and audience, and decides who is an admin from an allowlist of emails or roles. An OIDC authorization code login in the CA was rejected because it would add session, state, nonce and cookie signing code to the CA, which is the one place a mistake can mint credentials. Asking admins to paste bearer tokens was rejected as impractical and easy to leak. The admin UI is disabled unless all of the proxy settings are present, so a missing setting fails closed.

## Consequences

- The proxy keeps the admin's session in a cookie, so every request that changes state must be protected against cross-site requests by the CA itself (checking `Origin` and `Sec-Fetch-Site`), as the proxy does not do this.
- Admins are identified by the email claim of the proxy's JWT, which is recorded as who revoked a certificate.
