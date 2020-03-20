use clap::Clap;

#[derive(Clap)]
#[clap(version = "0.1", author = "James Dyson <theavitex@gmail.com>")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// DNSCAT client
    #[clap(name = "client")]
    Client(ClientOpts),
}

#[derive(Clap)]
struct ClientOpts {}

pub async fn start() {
    dotenv::dotenv().ok();
    env_logger::init();

    let opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Client(_client_opts) => {
            unimplemented!();
        }
    }
}
