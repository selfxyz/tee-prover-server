#!/bin/sh

# Check if required environment variables are set
if [ -z "$PROJECT_ID" ]; then
    echo "Error: PROJECT_ID environment variable is required"
    exit 1
fi

if [ -z "$POOL_NAME" ]; then
    echo "Error: POOL_NAME environment variable is required"
    exit 1
fi

# Create the updated creds.json content
cat > ./creds.json << EOF
{
  "type":"external_account",
  "audience":"//iam.googleapis.com/projects/${PROJECT_ID}/locations/global/workloadIdentityPools/${POOL_NAME}/providers/attestation-verifier",
  "subject_token_type":"urn:ietf:params:oauth:token-type:jwt",
  "token_url":"https://sts.googleapis.com/v1/token",
  "credential_source":{"file":"/run/container_launcher/attestation_verifier_claims_token"}
}
EOF

echo "Updated creds.json with PROJECT_ID=${PROJECT_ID} and POOL_NAME=${POOL_NAME}"
