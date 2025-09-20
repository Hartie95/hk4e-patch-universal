#![feature(str_from_utf16_endian)]

use std::{sync::RwLock};

use lazy_static::lazy_static;
use modules::{CcpBlocker, Misc};
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleFileNameA};
use std::ffi::CStr;
use std::path::Path;
use clap::Parser;
use url::Url;
use config::{ENDPOINTS};

mod interceptor;
mod marshal;
mod modules;
mod util;
mod config;

use crate::modules::{Http, MhyContext, ModuleManager, Security};

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
}

unsafe fn thread_func() {
    let mut module_manager = MODULE_MANAGER.write().unwrap();

    // Block query_security_file ASAP
    module_manager.enable(MhyContext::<CcpBlocker>::new(""));

    util::disable_memprotect_guard();
    Console::AllocConsole().unwrap();

    println!("Genshin Impact encryption patch\nMade by xeondev\n(Modded for all version > 5.0)");

    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    let exe_name = Path::new(exe_path).file_name().unwrap().to_str().unwrap();
    println!("Current executable name: {}", exe_name);

    if exe_name != "GenshinImpact.exe" && exe_name != "YuanShen.exe" {
        println!("Executable is not Genshin. Skipping initialization.");
        return;
    }

    let cli = Cli::parse();
    if let Some(redirect) = cli.redirect {
        println!("Setting up redirect: {}", redirect);
        ENDPOINTS.dispatch = Some(redirect.origin().unicode_serialization());
        ENDPOINTS.sdk = Some(redirect.origin().unicode_serialization());
    }
    if let Some(dispatch) = cli.dispatch {
        println!("Setting up dispatch redirect: {}", dispatch);
        ENDPOINTS.dispatch = Some(dispatch.origin().unicode_serialization());
    }
    if let Some(sdk) = cli.sdk {
        println!("Setting up sdk redirect: {}", sdk);
        ENDPOINTS.sdk = Some(sdk.origin().unicode_serialization());
    }

    println!("Initializing modules...");

    module_manager.enable(MhyContext::<Security>::new(&exe_name));
    marshal::find();
    module_manager.enable(MhyContext::<Http>::new(&exe_name));
    module_manager.enable(MhyContext::<Misc>::new(&exe_name));

    println!("Successfully initialized!");
}

lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        #[cfg(debug_assertions)]
        {
            thread_func();
        }
        #[cfg(not(debug_assertions))]
        {
            std::thread::spawn(|| thread_func());
        }
    }

    true
}
