-- Central, consolidated database (e.g., db "weblogs_central")

-- Optional dimension table if you want numeric IDs. Using text server_name is fine too.
CREATE TABLE IF NOT EXISTS servers (
  server_name text PRIMARY KEY
  -- optionally: metadata columns
);

-- Consolidated per-node facts
CREATE TABLE IF NOT EXISTS ip_counts_agg (
  bucket_start timestamptz NOT NULL,
  server_name  text NOT NULL REFERENCES servers(server_name) ON DELETE CASCADE,
  ip           inet NOT NULL,
  cnt          bigint NOT NULL,
  PRIMARY KEY (bucket_start, server_name, ip)
);

CREATE TABLE IF NOT EXISTS ua_counts_agg (
  bucket_start timestamptz NOT NULL,
  server_name  text NOT NULL REFERENCES servers(server_name) ON DELETE CASCADE,
  user_agent   text NOT NULL,
  cnt          bigint NOT NULL,
  PRIMARY KEY (bucket_start, server_name, user_agent)
);

-- Checkpointing which buckets have been synced from each node
CREATE TABLE IF NOT EXISTS sync_state (
  server_name text NOT NULL REFERENCES servers(server_name) ON DELETE CASCADE,
  table_name  text NOT NULL CHECK (table_name IN ('ip_counts','ua_counts')),
  last_bucket timestamptz NOT NULL,
  PRIMARY KEY (server_name, table_name)
);

-- Roll-up views (optional): totals across all servers
CREATE OR REPLACE VIEW v_ip_counts_total AS
SELECT bucket_start, ip, SUM(cnt) AS total
FROM ip_counts_agg
GROUP BY bucket_start, ip;

CREATE OR REPLACE VIEW v_ua_counts_total AS
SELECT bucket_start, user_agent, SUM(cnt) AS total
FROM ua_counts_agg
GROUP BY bucket_start, user_agent;

-- Time-range performance
CREATE INDEX IF NOT EXISTS ip_counts_agg_brin ON ip_counts_agg USING brin (bucket_start);
CREATE INDEX IF NOT EXISTS ua_counts_agg_brin ON ua_counts_agg USING brin (bucket_start);

CREATE OR REPLACE VIEW v_ip_total AS
SELECT bucket_start, SUM(cnt) AS total FROM ip_counts_agg
GROUP BY bucket_start;

CREATE OR REPLACE VIEW v_ua_total AS
SELECT bucket_start, SUM(cnt) AS total FROM ua_counts_agg
GROUP BY bucket_start;

