-- Tracks resources compromised via lethal trifecta violation.
-- Populated at fork time from pre-computed pending_compromises.

CREATE TABLE IF NOT EXISTS compromised_resources (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_path   TEXT NOT NULL,
    resource_type   TEXT NOT NULL,  -- "mount", "file", "external_endpoint"
    compromise_type TEXT NOT NULL,  -- "read", "write"
    data_type       TEXT NOT NULL,  -- which tag is compromised
    caused_by       TEXT NOT NULL,  -- policy_name that introduced trifecta
    via_path        TEXT NOT NULL,  -- JSON trace of the propagation path
    workflow_id     TEXT,           -- workflow that materialized the compromise
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_compromised_caused_by ON compromised_resources(caused_by);
CREATE INDEX IF NOT EXISTS idx_compromised_workflow ON compromised_resources(workflow_id);

-- Tracks per-policy taint classification computed at propose time.
-- Updated when a new policy is approved that affects the taint graph.

CREATE TABLE IF NOT EXISTS policy_taint (
    policy_name     TEXT PRIMARY KEY,
    taint_json      TEXT NOT NULL,  -- serialized PolicyTaint
    updated_at      TEXT NOT NULL
);
