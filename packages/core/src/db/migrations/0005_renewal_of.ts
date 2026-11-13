import type { Migration } from "../migrate.js"

export const migration: Migration = {
	name: "0005_renewal_of",
	statements: [
		// the serial of the host certificate a certificate is a renewal of, or
		// NULL if it was issued to a requester or recorded before this
		// migration without being matched below. It is not a foreign key, as
		// the certificate that was renewed may be removed by cleanup first
		"ALTER TABLE certificates ADD COLUMN renewal_of TEXT",
		"CREATE INDEX IF NOT EXISTS idx_certificates_renewal_of ON certificates(renewal_of)",
		// renewals recorded before this migration kept the requester of the
		// certificate they renewed. Each certificate revoked for renewal is
		// matched with the host certificate recorded after it for the same key,
		// principals and requester, whose validity started at most 15 seconds
		// before the revocation (a renewal is signed, then recorded with the
		// revocation). A match is only used when neither certificate matches
		// any other, so a certificate that cannot be told apart is left as it
		// was. The requester is only cleared by a later statement, so that a
		// chain of renewals is matched on requesters that are not yet changed.
		//
		// No index covers the key and principals, so the certificates that can
		// have been renewed are indexed for the match and the index is dropped
		// again, and each step is materialized once, so the match takes time in
		// proportion to the number of host certificates rather than its square.
		// The SQL may change for speed, but the name and result of a released
		// migration never do.
		"CREATE INDEX tmp_0005_renewal_candidates ON certificates(public_key, principals) WHERE certificate_type = 1 AND revocation_reason = 'renewal'",
		`WITH matches AS MATERIALIZED (
			SELECT renewed.id AS renewed_id, previous.serial AS previous_serial
			FROM certificates AS renewed
			JOIN certificates AS previous INDEXED BY tmp_0005_renewal_candidates
				ON previous.certificate_type = 1
				AND previous.revocation_reason = 'renewal'
				AND previous.public_key = renewed.public_key
				AND previous.principals = renewed.principals
				AND previous.id < renewed.id
				AND previous.requested_by IS renewed.requested_by
				AND unixepoch(previous.revoked_at, 'subsec') >= unixepoch(renewed.valid_after, 'subsec')
				AND unixepoch(previous.revoked_at, 'subsec') < unixepoch(renewed.valid_after, 'subsec', '+15 seconds')
			WHERE renewed.certificate_type = 1
		),
		renewed_once AS MATERIALIZED (
			SELECT renewed_id FROM matches GROUP BY renewed_id HAVING count(*) = 1
		),
		previous_once AS MATERIALIZED (
			SELECT previous_serial FROM matches GROUP BY previous_serial HAVING count(*) = 1
		),
		unique_matches AS MATERIALIZED (
			SELECT renewed_id, previous_serial FROM matches
			WHERE renewed_id IN (SELECT renewed_id FROM renewed_once)
			AND previous_serial IN (SELECT previous_serial FROM previous_once)
		)
		UPDATE certificates
		SET renewal_of = unique_matches.previous_serial
		FROM unique_matches
		WHERE certificates.id = unique_matches.renewed_id`,
		"DROP INDEX tmp_0005_renewal_candidates",
		// a renewal has no requester, as it is proven by possession of the
		// host key rather than by a requester's tokens
		"UPDATE certificates SET requested_by = NULL WHERE renewal_of IS NOT NULL",
	]
}
