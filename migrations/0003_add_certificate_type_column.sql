-- Migration number: 0003 	 2026-03-25T23:55:36.619Z
ALTER TABLE certificates ADD COLUMN certificate_type INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_certificates_certificate_type ON certificates(certificate_type);
