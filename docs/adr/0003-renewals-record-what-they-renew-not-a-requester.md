# Renewals record what they renew, not a requester

A renewed host certificate records the serial of the certificate it is a renewal of, and no requester. A renewal is proven by possession of the host key, usually by an automated client with no person involved, so recording a requester for it would claim that someone presented tokens for a certificate that nobody asked for. Carrying the requester forward from the renewed certificate was rejected because it made a renewal look the same as a request in the audit trail. Recording both the link and the original requester on every certificate in a chain was rejected because the link already leads back to the request, and the copy would claim the same thing as before.

How a certificate came to be issued is read from what it records: a requester for a request, a link to the renewed certificate for a renewal, and neither for a certificate recorded before the audit trail existed.

## Consequences

- The link is a serial rather than a foreign key, because cleanup can remove the renewed certificate while its renewal is still recorded. The link still shows that the certificate is a renewal after that, but no longer leads anywhere.
- The admin UI shows only the immediate links (the certificate a renewal renewed, and the certificate that renewed a revoked one) rather than following a chain back to the original requester, which for a host that renews daily would be hundreds of certificates long, and could be broken by cleanup.
- Renewals recorded before this change were matched to the certificates they renewed by a migration, which cleared their requester. Renewals that could not be matched with certainty keep the requester they were recorded with.
