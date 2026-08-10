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
    /// Env: PATCH_REDIRECT
    #[arg(long, env = "PATCH_REDIRECT", value_parser = parse_http_url)]
    redirect: Option<Url>,

    /// Redirects only the dispatch target (overrides --redirect for dispatch).
    /// Env: PATCH_DISPATCH_URL
    #[arg(long, env = "PATCH_DISPATCH_URL", value_parser = parse_http_url)]
    dispatch: Option<Url>,

    /// Redirects only SDK/“other” targets (overrides --redirect for sdk).
    /// Env: PATCH_SDK_URL
    #[arg(long, env = "PATCH_SDK_URL", value_parser = parse_http_url)]
    sdk: Option<Url>,

    /// Enables logging into files, not yet implemented
    /// Env: PATCH_FILE_LOG
    #[arg(long, env = "PATCH_FILE_LOG", default_missing_value="true")]
    file_log: Option<bool>,

    /// Enables all available logs
    /// Env: PATCH_LOG_ALL
    #[arg(long, env = "PATCH_LOG_ALL")]
    log_all: Option<bool>,

    /// Enables request redirection logging
    /// Env: PATCH_LOG_REQUESTS
    #[arg(long, env = "PATCH_LOG_REQUESTS", default_missing_value="true", num_args=0..=1)]
    log_requests: Option<bool>,

    /// Enables crypto key logging
    /// Env: PATCH_LOG_CRYPTO
    #[arg(long, env = "PATCH_LOG_CRYPTO", default_missing_value="true", num_args=0..=1)]
    log_crypto: Option<bool>,
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
    if let Some(log) = cli.log_all {
        println!("Enabling all logging: {}", log);
        config.log_config.log_connections = log;
        config.log_config.log_crypto_keys = log;
    }
    if let Some(log) = cli.log_crypto {
        println!("Enabling crypto key logging: {}", log);
        config.log_config.log_crypto_keys = log;
    }
    if let Some(log) = cli.log_requests {
        println!("Enabling connection redirection logging: {}", log);
        config.log_config.log_connections = log;
    }

    if let Some(log) = cli.file_log {
        println!("Enabling file logging (not yet implemented): {}", log);
        config.log_config.file_logging = log;
    }

    PATCHER_CONFIG.set(config).unwrap();
}
