-- Schema and notification trigger for the `proofs` table.
--
-- ⚠️  PRODUCTION AND STAGING SHARE ONE DATABASE. Both terraform.tfvars (the 7
-- production TEE workloads) and terraform.tfvars.staging use secret_id =
-- "DB_URL", so anything here reaches production immediately.
--
-- This file was regenerated on 2026-08-21 from the LIVE definitions
-- (pg_get_functiondef / pg_get_triggerdef / information_schema.columns), not
-- hand-edited. It had drifted far enough to be dangerous: applying the previous
-- version would have replaced the live trigger function with one that notified
-- the wrong channel and dropped two payload fields. That exact class of mistake
-- caused two production incidents on 2026-08-20.
--
-- If you need to change the trigger, read the deployed body FIRST
-- (`psql "$DB_URL" -c "\sf status_update_notify"`) and edit that. plpgsql is
-- late-bound, so CREATE OR REPLACE commits happily and then fails on every
-- subsequent INSERT/UPDATE -- the breakage does not show at apply time.
--
-- Also note there is a second, orphaned function in the live database,
-- `status_update_notify_staging()`, referenced by zero triggers. It is
-- deliberately not recreated here.

CREATE TABLE IF NOT EXISTS proofs (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_type SMALLINT NOT NULL,
    status SMALLINT DEFAULT 0,
    circuit_name VARCHAR(255) NOT NULL,
    onchain BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE,
    witness_generated_at TIMESTAMP WITH TIME ZONE,
    proof_generated_at TIMESTAMP WITH TIME ZONE,
    proof JSON,
    endpoint_type VARCHAR(128),
    endpoint VARCHAR(256),
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
    -- real failure reason behind pre-check metadata.
    precheck_verdict SMALLINT,
    precheck_reason TEXT,
    version SMALLINT DEFAULT 1,
    user_defined_data VARCHAR(768) DEFAULT '',
    self_defined_data VARCHAR(512) DEFAULT '',
    signature VARCHAR(132)
);

-- Idempotent, so this file is also safe to run against a database that predates
-- any of these columns. Types mirror the live table exactly; `version` in
-- particular is SMALLINT (not INTEGER) and `user_defined_data` is VARCHAR(768)
-- (not TEXT), because db-relayer's StatusUpdatePayload deserialises them by
-- type.
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS precheck_verdict SMALLINT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS precheck_reason TEXT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS version SMALLINT DEFAULT 1;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS user_defined_data VARCHAR(768) DEFAULT '';
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS self_defined_data VARCHAR(512) DEFAULT '';
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS signature VARCHAR(132);

-- Converge columns that EXIST but with the wrong type or default.
--
-- ADD COLUMN IF NOT EXISTS above is a no-op when the column is already there,
-- so a database created by an earlier version of this file keeps `version` as
-- INTEGER, `user_defined_data`/`self_defined_data` as TEXT, and `endpoint` at
-- VARCHAR(128) -- and an endpoint longer than 128 chars then fails to insert.
-- Since this file is the only schema source in the repo, rerunning it has to
-- actually converge.
--
-- Guarded on the current type so each block is a provable no-op against a
-- database already in the target shape (production is). That matters: two of
-- these are NARROWING conversions which rewrite the table and will fail loudly
-- if any existing value does not fit -- which is the correct outcome for a
-- database that has drifted, but must not be run blindly.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='proofs' AND column_name='endpoint'
               AND character_maximum_length IS DISTINCT FROM 256) THEN
    ALTER TABLE proofs ALTER COLUMN endpoint TYPE VARCHAR(256);
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='proofs' AND column_name='version'
               AND data_type <> 'smallint') THEN
    ALTER TABLE proofs ALTER COLUMN version TYPE SMALLINT;
  END IF;
  ALTER TABLE proofs ALTER COLUMN version SET DEFAULT 1;

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='proofs' AND column_name='user_defined_data'
               AND character_maximum_length IS DISTINCT FROM 768) THEN
    ALTER TABLE proofs ALTER COLUMN user_defined_data TYPE VARCHAR(768);
  END IF;
  ALTER TABLE proofs ALTER COLUMN user_defined_data SET DEFAULT '';

  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='proofs' AND column_name='self_defined_data'
               AND character_maximum_length IS DISTINCT FROM 512) THEN
    ALTER TABLE proofs ALTER COLUMN self_defined_data TYPE VARCHAR(512);
  END IF;
  ALTER TABLE proofs ALTER COLUMN self_defined_data SET DEFAULT '';

  ALTER TABLE proofs ALTER COLUMN request_id SET DEFAULT gen_random_uuid();
END $$;

-- Multichain / bridge columns present in the live table. Captured here so a
-- freshly provisioned database matches production; this file is the only
-- schema source in this repo, and code that reads these columns would fail
-- against a database created without them.
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS is_multichain BOOLEAN DEFAULT false;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS dest_chain_id BIGINT;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS dest_dapp_address VARCHAR(42);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS config_id VARCHAR(66);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS bridge_protocol VARCHAR(50);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS bridge_status VARCHAR(50);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS bridge_tx_hash VARCHAR(66);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS bridge_guid VARCHAR(66);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS bridge_eta VARCHAR(50);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS dest_tx_hash VARCHAR(66);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS dest_status VARCHAR(50);
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS bridged_at TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE proofs ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP WITHOUT TIME ZONE;

-- Body below is byte-for-byte the live pg_get_functiondef output, reformatted
-- only to CREATE OR REPLACE form. Three things here are load-bearing and were
-- each wrong in the previous version of this file:
--
--   * the channel is `status_update_staging`, in BOTH environments.
--     db-relayer reads get_secret("PG_CHANNEL", Some("status_update_staging"))
--     and the PG_CHANNEL secret does not exist, so production and staging
--     relayers both listen there. Notifying `status_update` reaches nobody.
--   * `version` and `user_defined_data` must be in the payload. Without
--     `version`, serde defaults it to 0 and the relayer rejects every disclose
--     with "Unsupported version: 0".
--   * `user_defined_data` must be COALESCE'd. It is a non-nullable String in
--     StatusUpdatePayload, and #[serde(default)] covers a MISSING key, not an
--     explicit null -- a null fails the whole notification with
--     "invalid type: null, expected a string".
--
-- The UPDATE guard fires on `status` only. It deliberately does NOT fire on
-- precheck_verdict: the verdict is written before the proof exists, and
-- notifying then would forward a row with no proof.
CREATE OR REPLACE FUNCTION status_update_notify() RETURNS trigger AS $$
DECLARE
  notification_payload JSON;
BEGIN
  IF (TG_OP = 'UPDATE' AND (
        NEW.status IS DISTINCT FROM OLD.status
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
      'version', NEW.version,
      'user_defined_data', COALESCE(NEW.user_defined_data, ''),
      'precheck_verdict', NEW.precheck_verdict,
      'precheck_reason', NEW.precheck_reason,
      'signature', NEW.signature
    );

    PERFORM pg_notify('status_update_staging', notification_payload::text);
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS status_update_notify ON proofs;
CREATE TRIGGER status_update_notify
AFTER UPDATE ON proofs
FOR EACH ROW
EXECUTE FUNCTION status_update_notify();

DROP TRIGGER IF EXISTS status_insert_notify ON proofs;
CREATE TRIGGER status_insert_notify
AFTER INSERT ON proofs
FOR EACH ROW
EXECUTE FUNCTION status_update_notify();
