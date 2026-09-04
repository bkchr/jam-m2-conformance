use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = m2_runner::cli::Cli::parse();
    std::process::exit(m2_runner::cli::run(cli).await);
}
