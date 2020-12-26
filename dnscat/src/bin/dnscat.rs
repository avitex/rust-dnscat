use dnscat::cli::client;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(version = "0.1", author = "avitex <avitex@wfxlabs.com>")]
pub(crate) struct Opts {
    #[structopt(subcommand)]
    app: SubCommand,
}

#[derive(StructOpt, Debug)]
enum SubCommand {
    /// DNSCAT client
    Client(client::App),
}

#[tokio::main]
async fn main() {
    let opts = Opts::from_args();

    match opts.app {
        SubCommand::Client(ref app) => app.run().await,
    }
}
