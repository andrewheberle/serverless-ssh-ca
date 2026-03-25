-- Migration number: 0002 	 2026-03-25T03:46:26.622Z
CREATE TABLE IF NOT EXISTS temp_certificates (
    id INTEGER PRIMARY KEY,
    serial TEXT UNIQUE,
    key_id TEXT,
    principals TEXT,
    extensions TEXT,
    valid_after TIMESTAMP,
    valid_before TIMESTAMP,
    revoked_at TIMESTAMP
);

INSERT INTO temp_certificates SELECT * FROM certificates;
DROP TABLE certificates;
ALTER TABLE temp_certificates RENAME TO certificates;

CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial);
CREATE INDEX IF NOT EXISTS idx_certificates_valid_after ON certificates(valid_after);
CREATE INDEX IF NOT EXISTS idx_certificates_valid_before ON certificates(valid_before);
CREATE INDEX IF NOT EXISTS idx_certificates_revoked_at ON certificates(revoked_at);
