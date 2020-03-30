use std::io;
use std::net::SocketAddr;

use trust_dns_resolver::config::Protocol;
use trust_dns_resolver::system_conf::read_system_conf;

pub fn get_system_dns_server() -> Result<Option<SocketAddr>, io::Error> {
    read_system_conf().map(|(config, _)| {
        config
            .name_servers()
            .iter()
            .filter(|server| server.protocol == Protocol::Udp)
            .map(|server| server.socket_addr)
            .next()
    })
}
