#[tokio::main]
async fn main() {
    dnscat::cli::start().await;
}
