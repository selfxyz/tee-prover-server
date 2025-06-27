use clap::Parser;

#[derive(Parser, Debug)]
pub struct Config {
    /// Web server bind address (e.g., 0.0.0.0:3001)
    #[arg(short, long, default_value = "0.0.0.0:3001")]
    pub server_address: String,

    /// PostgreSQL database connection URL
    #[arg(
        short,
        long,
        default_value = "postgres://postgres:mysecretpassword@localhost:5433/db"
    )]
    pub database_url: String,
    /// Circuit folder path
    #[arg(short = 'c', long, default_value = "../circuits")]
    pub circuit_folder: String,

    /// ZKey folder path
    #[arg(short = 'k', long, default_value = "./zkeys")]
    pub zkey_folder: String,

    /// Rapidsnark path
    #[arg(short = 'r', long, default_value = "./rapidsnark")]
    pub rapidsnark_path: String,
}
