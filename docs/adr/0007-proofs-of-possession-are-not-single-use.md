# Proofs of possession are not single-use

A proof of possession can be replayed to the request it was made for while its timestamp is within `CERTIFICATE_REQUEST_TIME_SKEW_MAX` (ADR 0006), and this stays so (#554). Making proofs single-use removes no risk. An issuance request carries the requester's access token and identity token alongside the proof, so anyone placed to capture an issuance proof has the tokens as well. With them they can make a proof with their own key, and get a certificate they can use for as long as the tokens are valid, which is far longer than the proof's window. Replaying the captured proof only issues a certificate for a key they don't hold. A renewal proof is already single-use, as a renewal revokes the certificate it renews in the same transaction. An attacker in the connection would use a renewal proof before its owner, so single-use proofs wouldn't stop them either. Revoking a certificate again does nothing. What needs protecting is the tokens, so proxies and logs in front of the CA must not record them or the proof.

## Considered Options

- **Remembering each accepted proof until its window ends**: needs a write on every request to a store that is strongly consistent, which on Workers means D1 rather than KV, for no reduction in risk.
- **A nonce issued by the CA**: adds a round trip and state for every request, and changes the 1.0 wire format, so the client and CA would have to be released together.
- **Signing a digest of the request body** (also rejected in ADR 0006): would stop an attacker in the connection from changing `lifetime`, `extensions` or `principals`. That attacker has the tokens anyway, and the change only affects a certificate for the requester's key, within what the CA allows. It would change the wire format of every client.

## Consequences

The proof format and the replay window stay as ADR 0006 describes. Revisit this if a request is ever authorized by a proof alone without being single-use already, as a renewal is, because the tokens would then no longer be the more valuable thing to capture.
