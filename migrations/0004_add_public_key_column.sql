-- Migration number: 0004 	 2026-03-31T00:20:32.333Z
ALTER TABLE certificates ADD COLUMN public_key TEXT;
