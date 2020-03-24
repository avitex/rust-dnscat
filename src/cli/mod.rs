mod client;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(version = "0.1", author = "James Dyson <theavitex@gmail.com>")]
pub(crate) struct Opts {
    #[structopt(subcommand)]
    subcmd: SubCommand,
}

#[derive(StructOpt, Debug)]
enum SubCommand {
    /// DNSCAT client
    #[structopt(name = "client")]
    Client(client::Opts),
}

pub async fn start() {
    dotenv::dotenv().ok();
    env_logger::init();

    let opts = Opts::from_args();

    match opts.subcmd {
        SubCommand::Client(ref client_opts) => client::start(client_opts).await,
    }
}
