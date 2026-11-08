# Proofs of possession are bound to the request

A proof of possession signs the request it is sent with: the HTTP method and the path, including any serial, are signed together with the timestamp and the key's fingerprint, in the `request-proof-of-possession@…` namespace. API v3 signed only the timestamp and fingerprint, in one namespace shared by every endpoint, so a proof captured from one v3 request could be replayed against any other v3 endpoint while the time window was open. For example, a proof sent to request a certificate could be reused to revoke a certificate for that key. So API v3 is removed in 1.0.0 with no deprecation release in between, and requests to its paths get `410 Gone`. The client has used only v4 since ssh-ca-client 0.24.0.

A v4 proof can still be replayed to the same request, with the same method and path, within `CERTIFICATE_REQUEST_TIME_SKEW_MAX` (90 seconds by default). This is accepted for 1.0, because such a replay gains nothing:

- **Issuing a certificate again**: also needs the requester's access token and identity token, and the new certificate is for a key the attacker does not hold.
- **Revoking again**: does nothing, because the certificate is already revoked.
- **Renewing again**: fails, because a renewal revokes the certificate it renews in the same transaction as it records the new one.

Making proofs single-use is tracked separately, in #554.

## Considered Options

- **Deprecating v3 for a release before removing it**: kept a known replay open for no benefit, as the only known client had already moved to v4.
- **Signing a digest of the request body as well**: would stop a replay from changing `lifetime`, `extensions` or `principals`. Rejected for 1.0 because the tokens are what authorize an issuance, a replayed issuance is for a key the attacker does not hold, and adding it would change the wire format of every client. It can be looked at again with #554.
- **A nonce from the CA, or remembering each proof until the window ends**: makes proofs single-use, but needs an extra round trip or server state on every request. Left to #554.
- **A tighter limit on timestamps from the future**: the window is the same on both sides of the CA's clock, so a proof from a client whose clock is ahead stays usable for up to twice the setting. Tightening it would make more requests fail because of client clock drift, for little gain.

## Consequences

- The proof format is part of what 1.0 promises, and stays exactly as it is: the `Proof-Of-Possession` header, `timestamp.fingerprint.signature`, and the `request-proof-of-possession@…` namespace. The `request-` prefix no longer distinguishes the namespace from another one, but renaming it would break every client.
- A client older than ssh-ca-client 0.24.0 cannot use a 1.0 CA.
