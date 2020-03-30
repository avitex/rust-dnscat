use dnscat::cli::client::App;

#[tokio::main]
async fn main() {
    App::new().run().await;
}
