pub mod file_generator;
pub mod proof_generator;
pub mod witness_generator;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Circuit {
    pub name: String,
    pub inputs: String, //json
}
