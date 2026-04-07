-- Mediator schema: workflow tokens, port allocations, active workflows, audit log.

CREATE TABLE IF NOT EXISTS workflow_tokens (
    token           TEXT      PRIMARY KEY,
    workflow_id     TEXT      NOT NULL,
    pid             INTEGER   NOT NULL,
    policy_name     TEXT      NOT NULL,
    inherited_from  TEXT      REFERENCES workflow_tokens(token),
    created_at      TEXT      NOT NULL
);

CREATE TABLE IF NOT EXISTS port_allocations (
    port            INTEGER   PRIMARY KEY,
    workflow_token  TEXT      NOT NULL REFERENCES workflow_tokens(token),
    allocated_at    TEXT      NOT NULL
);

CREATE TABLE IF NOT EXISTS active_workflows (
    workflow_id         TEXT    PRIMARY KEY,
    policy_name         TEXT    NOT NULL,
    root_pid            INTEGER NOT NULL,
    namespace_id        TEXT    NOT NULL,
    workflow_token      TEXT    NOT NULL REFERENCES workflow_tokens(token),
    parent_workflow_id  TEXT,
    started_at          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS ipc_messages (
    id                  INTEGER   PRIMARY KEY AUTOINCREMENT,
    sender_workflow_id  TEXT      NOT NULL,
    target_workflow_id  TEXT      NOT NULL,
    message             TEXT      NOT NULL,
    created_at          TEXT      NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER   PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT      NOT NULL,
    workflow_id     TEXT      NOT NULL,
    workflow_token  TEXT      NOT NULL,
    syscall         TEXT      NOT NULL,
    args            TEXT      NOT NULL,
    result          TEXT      NOT NULL,
    policy_used     TEXT      NOT NULL,
    details         TEXT
);
