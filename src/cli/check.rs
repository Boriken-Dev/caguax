//! `caguax check`: which rule and route a destination gets.

use clap::Args;
use serde_json::json;

use super::{Cli, Format, Outcome, OutputArgs, load_config, print_line};
use crate::config::{build_router, connection_for_target};
use crate::route::TlsSource;

/// `caguax check TARGET`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// A URL (`https://host/path`) or `HOST:PORT` (a `CONNECT` destination).
    pub target: String,

    /// The listener the connection arrives on: `proxy`, or a tunnel's name.
    #[arg(long, default_value = "proxy")]
    pub listener: String,

    /// The output format.
    #[command(flatten)]
    pub output: OutputArgs,
}

pub(super) fn run(cli: &Cli, args: &CheckArgs) -> Outcome {
    let loaded = load_config(cli)?;
    let router = build_router(&loaded.document, loaded.base_dir().as_deref())?;
    let connection = connection_for_target(&args.target, &args.listener)?;
    let explanation = router.explain(&connection);
    let route = explanation.route;
    let rule = match explanation.rule {
        Some(_) if !route.name().is_empty() => route.name().to_owned(),
        Some(_) => "matched".to_owned(),
        None => "default".to_owned(),
    };
    let credential = match route.tls() {
        Some(TlsSource::Credential(credential)) => Some(credential.name().to_owned()),
        Some(_) => Some("context".to_owned()),
        None => None,
    };
    let upstream = route.upstream().and_then(crate::upstream::Egress::spelling);
    let destination = connection.url();
    match args.output.chosen() {
        Format::Json => print_line(
            &json!({
                "destination": destination,
                "rule": rule,
                "action": route.action().as_str(),
                "credential": credential,
                "upstream": upstream,
            })
            .to_string(),
        ),
        Format::Text => {
            let mut parts = alloc::vec![
                alloc::format!("destination={destination}"),
                alloc::format!("rule={rule}"),
                alloc::format!("action={}", route.action()),
            ];
            if let Some(credential) = credential {
                parts.push(alloc::format!("credential={credential}"));
            }
            if let Some(upstream) = upstream {
                parts.push(alloc::format!("upstream={upstream}"));
            }
            print_line(&parts.join(" "))
        }
    }
}
