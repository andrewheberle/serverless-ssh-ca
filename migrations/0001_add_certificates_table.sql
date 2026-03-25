-- Migration number: 0001 	 2026-03-24T07:07:05.069Z
CREATE TABLE IF NOT EXISTS certificates (
    id INT PRIMARY KEY,
    serial TEXT UNIQUE,
    key_id TEXT,
    principals TEXT,
    extensions TEXT,
    valid_after TIMESTAMP,
    valid_before TIMESTAMP,
    revoked_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial);
CREATE INDEX IF NOT EXISTS idx_certificates_valid_after ON certificates(valid_after);
CREATE INDEX IF NOT EXISTS idx_certificates_valid_before ON certificates(valid_before);
CREATE INDEX IF NOT EXISTS idx_certificates_revoked_at ON certificates(revoked_at);
