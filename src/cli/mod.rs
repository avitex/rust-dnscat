mod client;

use clap::Clap;

use self::client::ClientOpts;

#[derive(Clap)]
#[clap(version = "0.1", author = "James Dyson <theavitex@gmail.com>")]
pub(crate) struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// DNSCAT client
    #[clap(name = "client")]
    Client(ClientOpts),
}

pub async fn start() {
    dotenv::dotenv().ok();
    env_logger::init();

    let opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Client(ref client_opts) => client::start(&opts, client_opts).await,
    }
}
