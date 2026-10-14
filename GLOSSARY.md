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

**Principal**:
A user name or host name that a certificate is valid for.
_Avoid_: Role (roles are identity token principals used to decide who may request host certificates), group

**Renewal**:
Issuing a new host certificate for the same key and principals as a current host certificate from this CA, in exchange for revoking it, proven by possession of the host key rather than by tokens.
_Avoid_: Refresh, re-issue
