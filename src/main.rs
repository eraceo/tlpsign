mod cli;
mod crypto;
mod protocol;
mod types;

fn main() {
    // Run the CLI and handle any fatal errors cleanly
    if let Err(e) = cli::run() {
        eprintln!("\n[FATAL ERROR] {}", e);
        std::process::exit(1);
    }
}
