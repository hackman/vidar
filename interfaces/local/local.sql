-- Local, per-node database (e.g., db "weblogs_local")
CREATE TABLE IF NOT EXISTS ip_counts (
  bucket_start timestamptz NOT NULL,
  ip inet NOT NULL,
  cnt bigint NOT NULL,
  PRIMARY KEY (bucket_start, ip)
);

CREATE TABLE IF NOT EXISTS ua_counts (
  bucket_start timestamptz NOT NULL,
  user_agent text NOT NULL,
  cnt bigint NOT NULL,
  PRIMARY KEY (bucket_start, user_agent)
);

-- Helpful indexes for time-range scans
CREATE INDEX IF NOT EXISTS ip_counts_brin ON ip_counts USING brin (bucket_start);
CREATE INDEX IF NOT EXISTS ua_counts_brin ON ua_counts USING brin (bucket_start);

