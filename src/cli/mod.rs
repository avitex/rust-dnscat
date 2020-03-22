mod client;

use clap::Clap;

#[derive(Clap, Debug)]
#[clap(version = "0.1", author = "James Dyson <theavitex@gmail.com>")]
pub(crate) struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    /// DNSCAT client
    #[clap(name = "client")]
    Client(client::Opts),
}

pub async fn start() {
    dotenv::dotenv().ok();
    env_logger::init();

    let opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Client(ref client_opts) => client::start(client_opts).await,
    }
}
