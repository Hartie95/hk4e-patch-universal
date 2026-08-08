use clap::Parser;
use url::Url;
use crate::config::{AppConfig, PATCHER_CONFIG};

fn parse_http_url(input: &str) -> Result<Url, String> {
    let mut u = Url::parse(input)
        .or_else(|_| Url::parse(&format!("http://{input}")))
        .map_err(|e| format!("invalid URL `{input}`: {e}"))?;

    match u.scheme() {
        "http" | "https" => {}
        s => return Err(format!("unsupported scheme `{s}` (only http/https)")),
    }
    if u.host().is_none() {
        return Err("missing host".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("credentials in URL are not allowed".into());
    }
    u.set_fragment(None);
    Ok(u)
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Redirects *all* targets (acts as default/base).
    /// Env: REDIRECT
    #[arg(long, env = "REDIRECT", value_parser = parse_http_url)]
    redirect: Option<Url>,

    /// Redirects only the dispatch target (overrides --redirect for dispatch).
    /// Env: DISPATCH_URL
    #[arg(long, env = "DISPATCH_URL", value_parser = parse_http_url)]
    dispatch: Option<Url>,

    /// Redirects only SDK/“other” targets (overrides --redirect for sdk).
    /// Env: SDK_URL
    #[arg(long, env = "SDK_URL", value_parser = parse_http_url)]
    sdk: Option<Url>,

    /// Redirects only SDK/“other” targets (overrides --redirect for sdk).
    /// Env: SDK_URL
    #[arg(long, env = "SDK_URL", value_parser = parse_http_url)]
    file_log: Option<bool>,
}

pub unsafe fn parse_parameters() {
    let cli = Cli::parse();
    let mut config: AppConfig = AppConfig::default();
    if let Some(redirect) = cli.redirect {
        println!("Setting up redirect: {}", redirect);
        config.redirect_config.dispatch = Some(redirect.origin().unicode_serialization());
        config.redirect_config.sdk = Some(redirect.origin().unicode_serialization());
        config.use_redirects = true;
    }
    if let Some(dispatch) = cli.dispatch {
        println!("Setting up dispatch redirect: {}", dispatch);
        config.redirect_config.dispatch = Some(dispatch.origin().unicode_serialization());
        config.use_redirects = true;
    }
    if let Some(sdk) = cli.sdk {
        println!("Setting up sdk redirect: {}", sdk);
        config.redirect_config.sdk = Some(sdk.origin().unicode_serialization());
        config.use_redirects = true;
    }

    PATCHER_CONFIG.set(config).unwrap();
}
