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
		// was. The requester is only cleared by the next statement, so that a
		// chain of renewals is matched on requesters that are not yet changed
		`WITH matches AS (
			SELECT renewed.id AS renewed_id, previous.serial AS previous_serial
			FROM certificates AS renewed
			JOIN certificates AS previous
				ON previous.certificate_type = 1
				AND previous.revocation_reason = 'renewal'
				AND previous.id < renewed.id
				AND previous.public_key = renewed.public_key
				AND previous.principals = renewed.principals
				AND previous.requested_by IS renewed.requested_by
				AND unixepoch(previous.revoked_at, 'subsec') >= unixepoch(renewed.valid_after, 'subsec')
				AND unixepoch(previous.revoked_at, 'subsec') < unixepoch(renewed.valid_after, 'subsec', '+15 seconds')
			WHERE renewed.certificate_type = 1
		),
		unique_matches AS (
			SELECT renewed_id, previous_serial FROM matches
			WHERE renewed_id IN (SELECT renewed_id FROM matches GROUP BY renewed_id HAVING count(*) = 1)
			AND previous_serial IN (SELECT previous_serial FROM matches GROUP BY previous_serial HAVING count(*) = 1)
		)
		UPDATE certificates
		SET renewal_of = (SELECT previous_serial FROM unique_matches WHERE renewed_id = certificates.id)
		WHERE id IN (SELECT renewed_id FROM unique_matches)`,
		// a renewal has no requester, as it is proven by possession of the
		// host key rather than by a requester's tokens
		"UPDATE certificates SET requested_by = NULL WHERE renewal_of IS NOT NULL",
	]
}
