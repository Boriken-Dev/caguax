//! `caguax pac`: the PAC script the proxy would serve.

use clap::Args;

use super::{Cli, Outcome, load_config, print_raw};
use crate::config::build_router;
use crate::pac::generate_pac;

/// `caguax pac`.
#[derive(Debug, Args)]
pub struct PacArgs {
    /// The proxy address the script points at, `HOST:PORT`. Omitted: the configuration's first
    /// listen address (port 3128 when it asks for a free one).
    #[arg(long, value_name = "HOST:PORT")]
    pub proxy: Option<String>,
}

pub(super) fn run(cli: &Cli, args: &PacArgs) -> Outcome {
    let loaded = load_config(cli)?;
    let router = build_router(&loaded.document, loaded.base_dir().as_deref())?;
    let proxy = match &args.proxy {
        Some(proxy) => proxy.clone(),
        None => match loaded.document.server.listen.first() {
            Some(first) => {
                let port = if first.port() == 0 {
                    3128
                } else {
                    first.port()
                };
                crate::connection::join_host(&first.address().to_string(), port)
            }
            None => "127.0.0.1:3128".to_owned(),
        },
    };
    let script = generate_pac(&router, &proxy, loaded.document.server.egress.as_ref());
    print_raw(&script)
}
