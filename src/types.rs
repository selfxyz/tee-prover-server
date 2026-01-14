use jsonrpsee::ResponsePayload;
use serde::{Deserialize, Serialize};

use crate::generator::Circuit;

/// Response to the initial handshake containing attestation and cryptographic suite information.
/// For PQXDH handshakes, includes X25519 and Kyber public keys for post-quantum security.
/// For legacy P-256 handshakes, the PQXDH fields are omitted.
#[derive(Serialize, Clone)]
pub struct HelloResponse {
    uuid: uuid::Uuid,
    attestation: Vec<u8>,
    /// Selected cryptographic suite: "Self-PQXDH-1" or "legacy-p256"
    selected_suite: String,
    /// Server's X25519 public key (32 bytes) for PQXDH handshakes
    #[serde(skip_serializing_if = "Option::is_none")]
    x25519_pubkey: Option<Vec<u8>>,
    /// Server's Kyber ML-KEM-768 encapsulation key (1184 bytes) for PQXDH handshakes
    #[serde(skip_serializing_if = "Option::is_none")]
    kyber_pubkey: Option<Vec<u8>>,
}

impl HelloResponse {
    /// Creates a new HelloResponse with the specified cryptographic suite and optional PQXDH keys.
    pub fn new(
        uuid: uuid::Uuid,
        attestation: Vec<u8>,
        selected_suite: String,
        x25519_pubkey: Option<Vec<u8>>,
        kyber_pubkey: Option<Vec<u8>>,
    ) -> Self {
        HelloResponse {
            uuid,
            attestation,
            selected_suite,
            x25519_pubkey,
            kyber_pubkey,
        }
    }
}

impl<'a> Into<ResponsePayload<'a, HelloResponse>> for HelloResponse {
    fn into(self) -> ResponsePayload<'a, HelloResponse> {
        ResponsePayload::success(self)
    }
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SubmitRequest {
    pub onchain: bool,
    #[serde(flatten)]
    pub proof_request_type: ProofRequest,
}

fn default_version() -> u32 {
    1
}

fn default_user_defined_data() -> String {
    "".to_string()
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum EndpointType {
    Celo,
    Https,
    StagingCelo,
    StagingHttps,
    TestCelo,
    TestHttps,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProofRequest {
    #[serde(rename_all = "camelCase")]
    Register {
        circuit: Circuit,
        endpoint_type: Option<EndpointType>,
        endpoint: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Dsc {
        circuit: Circuit,
        endpoint_type: Option<EndpointType>,
        endpoint: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Disclose {
        circuit: Circuit,
        endpoint_type: EndpointType,
        endpoint: String,
        #[serde(default = "default_user_defined_data")]
        user_defined_data: String,
        #[serde(default = "default_user_defined_data")]
        self_defined_data: String, 
        #[serde(default = "default_version")]
        version: u32,
    },
    #[serde(rename_all = "camelCase")]
    RegisterId {
        circuit: Circuit,
        endpoint_type: Option<EndpointType>,
        endpoint: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    DscId {
        circuit: Circuit,
        endpoint_type: Option<EndpointType>,
        endpoint: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    DiscloseId {
        circuit: Circuit,
        endpoint_type: EndpointType,
        endpoint: String,
        #[serde(default = "default_user_defined_data")]
        user_defined_data: String,
        #[serde(default = "default_user_defined_data")]
        self_defined_data: String, 
        #[serde(default = "default_version")]
        version: u32,
    },
    #[serde(rename_all = "camelCase")]
    RegisterAadhaar {
        circuit: Circuit,
        endpoint_type: Option<EndpointType>,
        endpoint: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    DiscloseAadhaar {
        circuit: Circuit,
        endpoint_type: EndpointType,
        endpoint: String,
        #[serde(default = "default_user_defined_data")]
        user_defined_data: String,
        #[serde(default = "default_user_defined_data")]
        self_defined_data: String, 
        #[serde(default = "default_version")]
        version: u32,
    },
}

impl ProofRequest {
    pub fn circuit(&self) -> &Circuit {
        match self {
            ProofRequest::Register { circuit, .. } => circuit,
            ProofRequest::Dsc { circuit, .. } => circuit,
            ProofRequest::Disclose { circuit, .. } => circuit,
            ProofRequest::RegisterId { circuit, .. } => circuit,
            ProofRequest::DscId { circuit, .. } => circuit,
            ProofRequest::DiscloseId { circuit, .. } => circuit,
            ProofRequest::RegisterAadhaar { circuit, .. } => circuit,
            ProofRequest::DiscloseAadhaar { circuit, .. } => circuit,
        }
    }
}

#[derive(Clone)]
pub enum ProofType {
    Register,
    Dsc,
    Disclose,
    RegisterId,
    DscId,
    DiscloseId,
    RegisterAadhaar,
    DiscloseAadhaar,
}

impl Into<ProofType> for &ProofRequest {
    fn into(self) -> ProofType {
        match self {
            ProofRequest::Register { .. } => ProofType::Register,
            ProofRequest::Dsc { .. } => ProofType::Dsc,
            ProofRequest::Disclose { .. } => ProofType::Disclose,
            ProofRequest::RegisterId { .. } => ProofType::RegisterId,
            ProofRequest::DscId { .. } => ProofType::DscId,
            ProofRequest::DiscloseId { .. } => ProofType::DiscloseId,
            ProofRequest::RegisterAadhaar { .. } => ProofType::RegisterAadhaar,
            ProofRequest::DiscloseAadhaar { .. } => ProofType::DiscloseAadhaar,
        }
    }
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofType::Register => write!(f, "register"),
            ProofType::Dsc => write!(f, "dsc"),
            ProofType::Disclose => write!(f, "disclose"),
            ProofType::RegisterId => write!(f, "register_id"),
            ProofType::DscId => write!(f, "dsc_id"),
            ProofType::DiscloseId => write!(f, "disclose_id"),
            ProofType::RegisterAadhaar => write!(f, "register_aadhaar"),
            ProofType::DiscloseAadhaar => write!(f, "disclose_aadhaar"),
        }
    }
}

impl Into<i32> for &ProofType {
    fn into(self) -> i32 {
        match self {
            ProofType::Register => 0,
            ProofType::Dsc => 1,
            ProofType::Disclose => 2,
            ProofType::RegisterId => 3,
            ProofType::DscId => 4,
            ProofType::DiscloseId => 5,
            ProofType::RegisterAadhaar => 6,
            ProofType::DiscloseAadhaar => 7,
        }
    }
}

impl TryFrom<i32> for ProofType {
    type Error = ();
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProofType::Register),
            1 => Ok(ProofType::Dsc),
            2 => Ok(ProofType::Disclose),
            3 => Ok(ProofType::RegisterId),
            4 => Ok(ProofType::DscId),
            5 => Ok(ProofType::DiscloseId),
            6 => Ok(ProofType::RegisterAadhaar),
            7 => Ok(ProofType::DiscloseAadhaar),
            _ => Err(()),
        }
    }
}

impl Into<i32> for ProofRequest {
    fn into(self) -> i32 {
        let proof_type: ProofType = (&self).into();
        (&proof_type).into()
    }
}
