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
    identifier VARCHAR(255)
    ,version INTEGER
    ,user_defined_data TEXT
    ,self_defined_data TEXT
    ,signature VARCHAR(132)
);

CREATE OR REPLACE FUNCTION status_update_notify() RETURNS trigger AS $$
DECLARE
  notification_payload JSON;
BEGIN
  IF (TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status) OR TG_OP = 'INSERT' THEN
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
      'identifier', NEW.identifier
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