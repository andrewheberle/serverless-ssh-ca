# Serverless SSH CA

A Certificate Authority that issues signed SSH certificates to users and hosts, trusting an OIDC identity provider to say who is asking.

## Language

**Requester**:
The person asking the CA to issue a certificate, as established from a verified access token and identity token for the same subject.
_Avoid_: User (ambiguous with user certificates), caller, client

**Access token**:
The token from the identity provider, sent in the `Authorization` header, that shows the requester is allowed to use the CA and gives their email address.
_Avoid_: Auth token, bearer token

**Identity token**:
The OIDC ID token, sent in the request body, that is issued for this CA and carries the requester's principals.
_Avoid_: ID token, id_token

**Certificate Authority**:
The CA itself: the key that signs certificates, and the rules for what certificate it will issue to whom and for how long.
_Avoid_: Signer, issuer (except for the `ISSUER_DN` of the CA key)

**CA public key**:
The public half of the key the Certificate Authority signs certificates with, which hosts and clients are configured to trust.
_Avoid_: CA certificate, root certificate (an SSH CA has no certificate of its own; "certificate" always means one the CA has issued)

**Principal**:
A user name or host name that a certificate is valid for.
_Avoid_: Role (roles are identity token principals used to decide who may request host certificates), group

**Renewal**:
Issuing a new host certificate for the same key and principals as a current host certificate from this CA, in exchange for revoking it, proven by a **proof of possession** of the host key rather than by tokens. A renewed certificate has no requester of its own; it records the certificate it is a renewal of, which leads back to the request the chain began with.
_Avoid_: Refresh, re-issue

**Proof of possession**:
A signature made with a key over a timestamp, the key's fingerprint and the request it is sent with, which shows that whoever sent the request holds that key. It is only valid for that one request, and only briefly.
_Avoid_: PoP, proof, signature

**Client address**:
The IP address a request to the CA came from, as reported by a proxy the CA is configured to trust. It records where a request came from, not who made it.
_Avoid_: Source IP, remote address, requester IP

**Admin**:
A person allowed to see every certificate the CA has issued and to revoke any of them, as established by an identity-aware proxy in front of the CA rather than by the tokens a requester presents.
_Avoid_: Administrator, operator, superuser

**Revocation**:
Marking an issued certificate as no longer trusted, so it appears in the KRL for its type until 24 hours after it expires. A certificate can be revoked by the holder of its key or by an admin. A revocation is never undone; access is restored by issuing a new certificate.
_Avoid_: Cancellation, deletion

**Revoker**:
Whoever is revoking a certificate, which decides whether they may: the holder of the key the certificate was issued for, proven by a **proof of possession** of that key, or an admin.
_Avoid_: Requester (a requester is authenticated by tokens, a revoker by what they hold or who they are)
