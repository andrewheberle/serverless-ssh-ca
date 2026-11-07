# Bulk revocation revokes the certificates the admin confirmed, not a filter

Admins need to revoke several certificates at once, mostly every valid certificate of a person who is leaving. We decided that a list filtered to valid certificates by principal or key ID links to a page that lists the matching certificates, each with a ticked box, and that the form on it sends the serials still ticked, with one reason and the confirmation. Only those serials are revoked, so what is revoked is exactly what the admin saw and confirmed, and the admin can leave out a certificate the filter matched by mistake, which matters as the key ID filter matches any key ID containing it. The page needs no JavaScript, so ADR-0004 is unchanged.

## Considered Options

- **Revoke whatever matches the filters when the form is sent**: simpler, but the admin never sees what is revoked, and a certificate issued between viewing the list and sending the form would be revoked without being seen.
- **A checkbox on every row of the list page**: without JavaScript there is no "select all", so revoking a person's certificates means ticking each one by hand, and the list's other filters and pages make the selection easy to lose.

## Consequences

- An unfiltered list, or one showing other statuses, offers no bulk revocation and the page refuses its filters, so revoking every valid certificate is never one click away. A serial filter alone matches one certificate, which its own revoke form covers.
- At most 50 certificates (a page of the list) are revoked at once. When more match, the admin revokes them a page at a time.
- Certificates are revoked in one transaction that increments the KRL revision once. Any that were revoked by someone else or expired since the page was shown are reported and the rest are still revoked, as a revocation is never undone and refusing them all would help nobody.
- Each certificate records the same revoker, reason and time as a single revocation would, with no identifier for the bulk action, so the audit trail and the database schema are unchanged.
