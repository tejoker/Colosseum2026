-- Commit the audit chain head into each anchored batch.
--
-- The keyed audit chain detects edits made without the sealing key. The operator
-- holds that key, so the chain alone cannot detect the operator rewriting and
-- re-sealing its own history. Recording the head in the batch — and committing
-- it as a merkle leaf under batch_root_hex, which is externally timestamped —
-- publishes "the log looked like this at time T" to something the operator does
-- not control. Any later rewrite contradicts that commitment.
ALTER TABLE agent_action_anchors
    ADD COLUMN IF NOT EXISTS audit_head_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE agent_action_anchors
    ADD COLUMN IF NOT EXISTS audit_head_hash TEXT NOT NULL DEFAULT '';
