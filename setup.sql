CREATE TABLE IF NOT EXISTS proofs (
    request_id UUID PRIMARY KEY,
    proof_type SMALLINT NOT NULL,
    status SMALLINT DEFAULT 0,
    circuit_name VARCHAR(255) NOT NULL,
    onchain BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE,
    witness_generated_at TIMESTAMP WITH TIME ZONE,
    proof_generated_at TIMESTAMP WITH TIME ZONE,
    proof JSON,
    endpoint_type VARCHAR(128),
    endpoint VARCHAR(128),
    public_inputs TEXT[],
    reason TEXT,
    identifier VARCHAR(255),
    -- Signature pre-check verdict (0 = valid, 1 = invalid, 2 = unavailable --
    -- see src/db/types.rs's PrecheckVerdict), recorded on every request
    -- regardless of outcome. Nullable and a DEDICATED column, not `reason`:
    -- a pre-check note is informational and may sit next to any status
    -- (including a proof that later succeeded), while `reason` explains why
    -- a request produced nothing. Conflating them would make a passing
    -- request with a stray pre-check note look like a failure, or hide the
    -- real failure reason behind pre-check metadata. Nullable so existing
    -- rows, and any request predating the pre-check, stay valid.
    precheck_verdict SMALLINT,
    precheck_reason TEXT
    ,version INTEGER
    ,user_defined_data TEXT
    ,self_defined_data TEXT
    ,signature VARCHAR(132)
);

-- Idempotent for databases where the table already existed before these
-- columns were added; a no-op on a fresh CREATE TABLE above.
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS precheck_verdict SMALLINT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS precheck_reason TEXT;

CREATE OR REPLACE FUNCTION status_update_notify() RETURNS trigger AS $$
DECLARE
  notification_payload JSON;
BEGIN
  -- Every column the payload below carries must appear here, or a write that
  -- touches only that column sends nothing and the consumer never learns of it.
  -- `signature` was added to the payload without being added to this condition:
  -- correct only by accident, because update_proof happens to set `status` in the
  -- same statement. A backfill, a re-sign, or any future write that updates the
  -- signature alone would have been silently dropped.
  IF (TG_OP = 'UPDATE' AND (
        NEW.status IS DISTINCT FROM OLD.status
        OR NEW.precheck_verdict IS DISTINCT FROM OLD.precheck_verdict
        OR NEW.signature IS DISTINCT FROM OLD.signature
      )) OR TG_OP = 'INSERT' THEN
    notification_payload = json_build_object(
      'request_id', NEW.request_id,
      'proof_type', NEW.proof_type,
      'status', NEW.status,
      'created_at', NEW.created_at,
      'circuit_name', NEW.circuit_name,
      'onchain', NEW.onchain,
      'witness_generated_at', NEW.witness_generated_at,
      'proof_generated_at', NEW.proof_generated_at,
      'proof', NEW.proof,
      'endpoint_type', NEW.endpoint_type,
      'endpoint', NEW.endpoint,
      'public_inputs', NEW.public_inputs,
      'reason', NEW.reason,
      'identifier', NEW.identifier,
      'precheck_verdict', NEW.precheck_verdict,
      'precheck_reason', NEW.precheck_reason
      ,'signature', NEW.signature
    );

    PERFORM pg_notify('status_update', notification_payload::text);
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS status_update_notify ON proofs;
CREATE TRIGGER status_update_notify
AFTER UPDATE ON proofs
FOR EACH ROW
EXECUTE PROCEDURE status_update_notify();

DROP TRIGGER IF EXISTS status_insert_notify ON proofs;
CREATE TRIGGER status_insert_notify
AFTER INSERT ON proofs
FOR EACH ROW
EXECUTE PROCEDURE status_update_notify();

ALTER TABLE proofs ADD COLUMN IF NOT EXISTS version INTEGER;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS user_defined_data TEXT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS self_defined_data TEXT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS signature VARCHAR(132);