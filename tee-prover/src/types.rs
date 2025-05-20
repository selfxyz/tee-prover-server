use jsonrpsee::ResponsePayload;
use serde::{Deserialize, Serialize};

use crate::generator::Circuit;

#[derive(Serialize, Clone)]
pub struct HelloResponse {
    uuid: uuid::Uuid,
    attestation: Vec<u8>,
}

impl HelloResponse {
    pub fn new(uuid: uuid::Uuid, attestation: Vec<u8>) -> Self {
        HelloResponse { uuid, attestation }
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
