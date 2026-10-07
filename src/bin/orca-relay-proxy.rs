use std::{env, net::SocketAddr};

use anyhow::{bail, Context, Result};
use orca_relay::adapter::{run_proxy_with_server_ids, ProxyConfig};
use tokio::signal;

const USAGE: &str = "Usage: orca-relay-proxy [--bind <addr>] --relay-url <url> --server-id <id> [--server-ids <ids>] --client-id <id>\n\nConfiguration:\n  --bind <addr>        Local proxy bind address (or ORCA_RELAY_BIND; default 127.0.0.1:0)\n  --relay-url <url>    Relay WebSocket URL (or ORCA_RELAY_URL)\n  --server-id <id>     Default relay server id for / and /ws (or ORCA_RELAY_SERVER_ID)\n  --server-ids <ids>   Optional comma-separated server ids also reachable via /r/<id> and /r/<id>/ws\n                       (or ORCA_RELAY_SERVER_IDS)\n  --client-id <id>     Relay client id (or ORCA_RELAY_CLIENT_ID)\n  ORCA_RELAY_TOKEN     Relay bearer token (required; environment only)\n\nThe relay token is intentionally not accepted as a CLI flag.\n";

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse()?;
    if args.help {
        print!("{USAGE}");
        return Ok(());
    }

    let bind = args
        .bind
        .or_else(|| env::var("ORCA_RELAY_BIND").ok())
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let bind_addr: SocketAddr = bind.parse().context("invalid proxy bind address")?;
    let relay_url = required(args.relay_url, "ORCA_RELAY_URL", "--relay-url")?;
    let server_id = required(args.server_id, "ORCA_RELAY_SERVER_ID", "--server-id")?;
    let client_id = required(args.client_id, "ORCA_RELAY_CLIENT_ID", "--client-id")?;
    let server_ids =
        resolve_server_ids(args.server_ids, || env::var("ORCA_RELAY_SERVER_IDS").ok())?;
    let additional_routes = !server_ids.is_empty();
    let relay_token = env::var("ORCA_RELAY_TOKEN").context("missing ORCA_RELAY_TOKEN")?;

    let proxy = run_proxy_with_server_ids(
        ProxyConfig {
            bind_addr,
            relay_url,
            server_id,
            relay_token,
            client_id,
        },
        server_ids,
    )
    .await?;

    let port = proxy.local_addr().port();
    println!("orca-relay-proxy listening on local port {port}");
    println!("forwarding via the configured relay");
    if additional_routes {
        println!("additional runtime routes are enabled");
    }
    println!("press Ctrl-C to stop");
    signal::ctrl_c()
        .await
        .context("failed to wait for Ctrl-C")?;
    Ok(())
}

#[derive(Default)]
struct Args {
    bind: Option<String>,
    relay_url: Option<String>,
    server_id: Option<String>,
    server_ids: Option<String>,
    client_id: Option<String>,
    help: bool,
}

impl Args {
    fn parse() -> Result<Self> {
        Self::parse_from(env::args().skip(1))
    }

    fn parse_from(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut parsed = Self::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => parsed.help = true,
                "--bind" => parsed.bind = Some(value_after(&mut args, "--bind")?),
                "--relay-url" => parsed.relay_url = Some(value_after(&mut args, "--relay-url")?),
                "--server-id" => parsed.server_id = Some(value_after(&mut args, "--server-id")?),
                "--server-ids" => parsed.server_ids = Some(value_after(&mut args, "--server-ids")?),
                "--client-id" => parsed.client_id = Some(value_after(&mut args, "--client-id")?),
                _ if arg.starts_with("--bind=") => {
                    parsed.bind = Some(value_after_equals(&arg, "--bind")?)
                }
                _ if arg.starts_with("--relay-url=") => {
                    parsed.relay_url = Some(value_after_equals(&arg, "--relay-url")?)
                }
                _ if arg.starts_with("--server-id=") => {
                    parsed.server_id = Some(value_after_equals(&arg, "--server-id")?)
                }
                _ if arg.starts_with("--server-ids=") => {
                    parsed.server_ids = Some(value_after_equals(&arg, "--server-ids")?)
                }
                _ if arg.starts_with("--client-id=") => {
                    parsed.client_id = Some(value_after_equals(&arg, "--client-id")?)
                }
                _ if arg.starts_with('-') => bail!("unknown option; run orca-relay-proxy --help"),
                _ => bail!("unexpected positional argument; run orca-relay-proxy --help"),
            }
        }
        Ok(parsed)
    }
}

fn required(flag_value: Option<String>, env_name: &str, flag_name: &str) -> Result<String> {
    flag_value
        .or_else(|| env::var(env_name).ok())
        .with_context(|| format!("missing {env_name} or {flag_name}"))
}

/// The flag wins over the environment; `env_value` is injectable so tests never touch real env.
fn resolve_server_ids(
    flag_value: Option<String>,
    env_value: impl FnOnce() -> Option<String>,
) -> Result<Vec<String>> {
    match flag_value.or_else(env_value) {
        Some(raw) => parse_server_ids(&raw),
        None => Ok(Vec::new()),
    }
}

fn parse_server_ids(raw: &str) -> Result<Vec<String>> {
    let mut server_ids = Vec::new();
    for server_id in raw.split(',') {
        let server_id = server_id.trim();
        if server_id.is_empty() {
            bail!("invalid ORCA_RELAY_SERVER_IDS or --server-ids: blank or empty server id");
        }
        server_ids.push(server_id.to_string());
    }
    Ok(server_ids)
}

fn value_after(args: &mut impl Iterator<Item = String>, flag_name: &str) -> Result<String> {
    let value = args
        .next()
        .with_context(|| format!("missing value for {flag_name}"))?;
    if value.is_empty() {
        bail!("empty value for {flag_name}");
    }
    Ok(value)
}

fn value_after_equals(arg: &str, flag_name: &str) -> Result<String> {
    let Some((_, value)) = arg.split_once('=') else {
        bail!("missing value for {flag_name}");
    };
    if value.is_empty() {
        bail!("empty value for {flag_name}");
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Result<Args> {
        Args::parse_from(values.iter().map(|value| value.to_string()))
    }

    #[test]
    fn server_ids_flag_accepts_separate_and_equals_forms() {
        let separate = args(&["--server-ids", "alpha,beta"]).unwrap();
        assert_eq!(separate.server_ids.as_deref(), Some("alpha,beta"));
        let equals = args(&["--server-ids=alpha,beta"]).unwrap();
        assert_eq!(equals.server_ids.as_deref(), Some("alpha,beta"));
        let default = args(&["--server-id=alpha"]).unwrap();
        assert_eq!(default.server_id.as_deref(), Some("alpha"));
        assert!(default.server_ids.is_none());
    }

    #[test]
    fn server_ids_flag_rejects_missing_or_empty_values() {
        assert!(args(&["--server-ids"]).is_err());
        assert!(args(&["--server-ids", ""]).is_err());
        assert!(args(&["--server-ids="]).is_err());
    }

    #[test]
    fn parse_server_ids_trims_entries() {
        assert_eq!(
            parse_server_ids(" alpha , beta gamma,ws ").unwrap(),
            vec!["alpha", "beta gamma", "ws"]
        );
    }

    #[test]
    fn parse_server_ids_rejects_blank_entries_without_echoing_input() {
        for raw in ["", "   ", "alpha,,beta", "alpha,", ",alpha", "alpha, ,beta"] {
            let error = parse_server_ids(raw).unwrap_err().to_string();
            assert!(!error.contains("alpha"));
        }
    }

    #[test]
    fn resolve_server_ids_prefers_flag_over_env() {
        let resolved =
            resolve_server_ids(Some("from-flag".into()), || Some("from-env".into())).unwrap();
        assert_eq!(resolved, vec!["from-flag"]);
        let resolved = resolve_server_ids(None, || Some("from-env".into())).unwrap();
        assert_eq!(resolved, vec!["from-env"]);
        assert!(resolve_server_ids(None, || None).unwrap().is_empty());
    }

    #[test]
    fn resolve_server_ids_rejects_blank_env_value() {
        assert!(resolve_server_ids(None, || Some(String::new())).is_err());
        assert!(resolve_server_ids(None, || Some(" , ".into())).is_err());
    }
}
