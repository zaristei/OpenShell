-- Add UID column to workflow_tokens and active_workflows for UID-based isolation.
-- The namespace_id column is retained for backwards compatibility but is no longer
-- used for new workflows (UID stored in the uid column instead).

ALTER TABLE workflow_tokens ADD COLUMN uid INTEGER;
ALTER TABLE active_workflows ADD COLUMN uid INTEGER;
