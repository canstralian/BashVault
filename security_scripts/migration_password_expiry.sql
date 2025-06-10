
ALTER TABLE passwords ADD COLUMN expiry_date TEXT DEFAULT NULL;
ALTER TABLE passwords ADD COLUMN status TEXT DEFAULT 'active';
-- Use ISO 8601 dates for expiry_date, e.g. '2025-06-10T00:00:00Z'
