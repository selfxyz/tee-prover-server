use clap::Parser;

/// How the signature pre-check's verdict affects the request.
///
/// Two modes, not three: an intermediate mode that rejected `invalid` while
/// forwarding `unavailable` existed at one point in this project's history
/// and was removed once the residual unverifiable set was driven to zero --
/// with nothing legitimate left to forward, such a mode would only invite
/// forwarding a genuine coverage gap.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum PrecheckMode {
    /// Every verdict is recorded but nothing is rejected. Behaviour
    /// identical to a build with no pre-check at all.
    Shadow,
    /// `invalid` and `unavailable` both reject, before witness generation.
    Enforce,
}

#[derive(Parser, Debug)]
pub struct Config {
    /// Web server bind address (e.g., 0.0.0.0:3001)
    #[arg(short, long, default_value = "0.0.0.0:3001")]
    pub server_address: String,

    /// Secret manager project id
    #[arg(short, long)]
    pub project_id: String,

    /// Secret manager secret id
    #[arg(short, long, default_value = "DB_URL")]
    pub secret_id: String,

    /// Circuit folder path
    #[arg(short = 'c', long, default_value = "../circuits")]
    pub circuit_folder: String,

    /// ZKey folder path
    #[arg(short = 'k', long, default_value = "./zkeys")]
    pub zkey_folder: String,

    /// Rapidsnark path
    #[arg(short = 'r', long, default_value = "./rapidsnark")]
    pub rapidsnark_path: String,

    /// Signature pre-check enforcement mode (`shadow` | `enforce`).
    ///
    /// Defaults to `enforce` here too, matching the image's own default in
    /// `start.sh` -- this default only matters for an invocation that
    /// bypasses `start.sh` entirely, since `start.sh` always passes the flag
    /// explicitly.
    #[arg(long, value_enum, default_value = "enforce")]
    pub precheck_mode: PrecheckMode,
}
