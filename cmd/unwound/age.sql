-- Persistent domain-age evidence. The age worker is the only writer.
-- Set journal_mode=WAL, foreign_keys=ON, and busy_timeout on the connection.
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS domain_age (
    domain TEXT PRIMARY KEY COLLATE BINARY,
    source TEXT NOT NULL CHECK (source IN ('rdap', 'crtsh', 'none')),
    status TEXT NOT NULL CHECK (status IN ('valid', 'history', 'unknown', 'error')),
    registered_at INTEGER,
    effective_at INTEGER,
    ct_first_seen_at INTEGER,
    fetched_at INTEGER NOT NULL,
    retry_after INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    evidence_uri TEXT,
    psl_generation TEXT NOT NULL,
    bootstrap_generation TEXT NOT NULL,
    last_check_id INTEGER REFERENCES age_check(id),
    CHECK (length(domain) BETWEEN 1 AND 253 AND domain = lower(domain)),
    CHECK (registered_at IS NULL OR registered_at <= effective_at),
    CHECK (effective_at IS NULL OR effective_at <= fetched_at),
    CHECK (ct_first_seen_at IS NULL OR ct_first_seen_at <= fetched_at),
    CHECK (status != 'valid' OR
           (source = 'rdap' AND registered_at IS NOT NULL AND effective_at IS NOT NULL)),
    CHECK (status != 'history' OR
           (source = 'crtsh' AND ct_first_seen_at IS NOT NULL))
) STRICT;

CREATE INDEX IF NOT EXISTS domain_age_lru ON domain_age(last_used_at, domain);
CREATE INDEX IF NOT EXISTS domain_age_retry ON domain_age(retry_after);

-- A cached row may pin only a check of that exact registered domain. Keep
-- this invariant even if a connection forgets to enable foreign_keys.
CREATE TRIGGER IF NOT EXISTS domain_age_check_insert BEFORE INSERT ON domain_age
WHEN NEW.last_check_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM age_check WHERE id = NEW.last_check_id AND domain = NEW.domain
)
BEGIN
    SELECT RAISE(ABORT, 'last_check_id belongs to another domain');
END;

CREATE TRIGGER IF NOT EXISTS domain_age_check_update
BEFORE UPDATE OF last_check_id, domain ON domain_age
WHEN NEW.last_check_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM age_check WHERE id = NEW.last_check_id AND domain = NEW.domain
)
BEGIN
    SELECT RAISE(ABORT, 'last_check_id belongs to another domain');
END;

CREATE TRIGGER IF NOT EXISTS domain_age_limit AFTER INSERT ON domain_age
WHEN (SELECT count(*) FROM domain_age) > 20000
BEGIN
    DELETE FROM domain_age WHERE domain IN (
        SELECT domain FROM domain_age ORDER BY last_used_at, domain
        LIMIT (SELECT count(*) - 20000 FROM domain_age)
    );
END;

-- One row for each external age check, including attempts that fail. This is
-- intentionally independent of domain_age so LRU eviction does not erase the
-- first request that caused an RDAP/crt.sh lookup. A scheduled refresh has no DNS
-- request. Attribution stops at the kernel-bound socket UID. The process
-- columns remain NULL and are retained for schema compatibility.
CREATE TABLE IF NOT EXISTS age_check (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL COLLATE BINARY,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    cause TEXT NOT NULL CHECK (cause IN ('miss', 'retry', 'refresh')),
    request_id INTEGER,
    dns_id INTEGER CHECK (dns_id BETWEEN 0 AND 65535),
    qname TEXT,
    qtype INTEGER CHECK (qtype BETWEEN 1 AND 65535),
    transport TEXT CHECK (transport IN ('udp', 'tcp')),
    source_label TEXT,
    service_uid INTEGER,
    policy_namespace TEXT,
    policy_generation INTEGER,
    provenance TEXT NOT NULL CHECK (provenance IN ('uid_only', 'kernel_verified', 'scheduled')),
    process_pid INTEGER,
    process_start_ticks INTEGER,
    process_exe TEXT,
    netns_inode INTEGER,
    rdap_result TEXT CHECK (rdap_result IN ('valid', 'unknown', 'error')),
    crtsh_result TEXT CHECK (crtsh_result IN ('history', 'none', 'error')),
    CHECK (length(domain) BETWEEN 1 AND 253 AND domain = lower(domain)),
    CHECK ((cause = 'refresh' AND provenance = 'scheduled' AND request_id IS NULL)
        OR (cause != 'refresh' AND provenance != 'scheduled' AND request_id IS NOT NULL
            AND dns_id IS NOT NULL AND qname IS NOT NULL AND qtype IS NOT NULL
            AND transport IS NOT NULL AND source_label IS NOT NULL
            AND service_uid IS NOT NULL AND policy_namespace IS NOT NULL
            AND policy_generation IS NOT NULL)),
    CHECK ((provenance = 'kernel_verified' AND process_pid IS NOT NULL
            AND process_start_ticks IS NOT NULL AND process_exe IS NOT NULL
            AND netns_inode IS NOT NULL)
        OR (provenance != 'kernel_verified' AND process_pid IS NULL
            AND process_start_ticks IS NULL AND process_exe IS NULL
            AND netns_inode IS NULL))
) STRICT;

CREATE INDEX IF NOT EXISTS age_check_domain_time ON age_check(domain, started_at DESC);
CREATE INDEX IF NOT EXISTS age_check_time ON age_check(started_at);

-- The writer may finish a check by setting its result fields, but the
-- triggering request and process attribution are immutable once recorded.
CREATE TRIGGER IF NOT EXISTS age_check_provenance_immutable
BEFORE UPDATE OF domain, started_at, cause, request_id, dns_id, qname, qtype,
    transport, source_label, service_uid, policy_namespace, policy_generation,
    provenance, process_pid, process_start_ticks, process_exe, netns_inode
ON age_check
BEGIN
    SELECT RAISE(ABORT, 'age check provenance is immutable');
END;

-- Check history is bounded independently of the indefinitely retained LRU
-- evidence rows. Prune a batch only when the table grows past 120,000 checks;
-- never remove a cached domain's latest check. These row limits are what
-- bound the database's size; SQLite's automatic checkpoint bounds its WAL.
CREATE TRIGGER IF NOT EXISTS age_check_limit AFTER INSERT ON age_check
WHEN (SELECT count(*) FROM age_check) > 120000
BEGIN
    DELETE FROM age_check WHERE id IN (
        SELECT id FROM age_check
        WHERE id NOT IN (
            SELECT last_check_id FROM domain_age WHERE last_check_id IS NOT NULL
        )
        ORDER BY id LIMIT 1024
    );
END;
