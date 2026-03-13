use clap::{Parser, Subcommand};

pub mod revoke_cmd;
pub mod sign_cmd;
pub mod solve_cmd;
pub mod verify_cmd;

#[derive(Parser)]
#[command(
    name = "tlpsign",
    version = "1.0",
    about = "Deferred Deterministic Signature Protocol",
    long_about = "A cryptographic protocol for time-locked signature verification with an optional revocation mechanism, requiring no trusted third party."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a document and lock the signature behind a time-lock puzzle
    Sign {
        #[arg(long)]
        document: String,
        #[arg(long, help = "Delay format, e.g., '180d', '24h', '60m', '300s'")]
        delay: String,
        #[arg(
            long,
            default_value_t = 3,
            help = "Multiplier against faster adversary hardware"
        )]
        multiplier: u32,
        #[arg(long)]
        output: String,
        #[arg(
            long,
            default_value = "Unknown hardware",
            help = "Hardware description for metadata"
        )]
        hardware_note: String,
    },
    /// Verify a document against a previously generated bundle
    Verify {
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        document: String,
    },
    /// Revoke a bundle using the revocation key
    Revoke {
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        revocation_key: String,
    },
    /// Solve the time-lock puzzle and extract cryptographic material
    Solve {
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        output: String,
    },
}

/// Helper to parse delays like "180d" into seconds
fn parse_delay(delay: &str) -> Result<u64, String> {
    let s = delay.trim();
    if s.is_empty() {
        return Err("Delay string is empty".to_string());
    }

    let (num_str, unit) = s.split_at(s.len().saturating_sub(1));
    let num: u64 = num_str
        .parse()
        .map_err(|_| "Invalid number in delay format")?;

    match unit {
        "s" => Ok(num),
        "m" => Ok(num * 60),
        "h" => Ok(num * 3600),
        "d" => Ok(num * 86400),
        _ => Err("Invalid delay unit. Must be s, m, h, or d (e.g., '180d')".to_string()),
    }
}

pub fn run() -> Result<(), String> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Sign {
            document,
            delay,
            multiplier,
            output,
            hardware_note,
        } => {
            let delay_sec = parse_delay(delay)?;
            sign_cmd::execute(document, delay_sec, *multiplier, output, hardware_note)
        }
        Commands::Verify { bundle, document } => verify_cmd::execute(bundle, document),
        Commands::Revoke {
            bundle,
            revocation_key,
        } => revoke_cmd::execute(bundle, revocation_key),
        Commands::Solve { bundle, output } => solve_cmd::execute(bundle, output),
    }
}
