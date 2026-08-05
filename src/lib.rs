#![feature(str_from_utf16_endian)]

use std::{sync::RwLock, thread};

use lazy_static::lazy_static;
use modules::{CcpBlocker, Misc};
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleFileNameA};
use std::ffi::CStr;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use clap::Parser;
use url::Url;
use windows::core::s;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use config::{ENDPOINTS};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

mod interceptor;
mod marshal;
mod modules;
mod util;
mod config;

use crate::modules::{Http, MhyContext, ModuleManager, Security, HoYoPass};

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
const UA_DLL_NAME: &str = "UserAssembly.dll";

unsafe fn initConsole(){
    Console::AllocConsole().unwrap();
    println!("Genshin Impact encryption patch\nMade by xeondev\nmodded by hartie95 for chainload");
}

unsafe fn thread_func() {

    let mut module_manager = MODULE_MANAGER.write().unwrap();

    // Block query_security_file ASAP
    let _ = module_manager.enable(MhyContext::<CcpBlocker>::new(""));

    // todo only skip if mhynot2 is loaded
    //util::disable_memprotect_guard();

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

    let mut usesRedirect = false;

    let cli = Cli::parse();
    if let Some(redirect) = cli.redirect {
        println!("Setting up redirect: {}", redirect);
        ENDPOINTS.dispatch = Some(redirect.origin().unicode_serialization());
        ENDPOINTS.sdk = Some(redirect.origin().unicode_serialization());
        usesRedirect = true;
    }
    if let Some(dispatch) = cli.dispatch {
        println!("Setting up dispatch redirect: {}", dispatch);
        ENDPOINTS.dispatch = Some(dispatch.origin().unicode_serialization());
        usesRedirect = true;
    }
    if let Some(sdk) = cli.sdk {
        println!("Setting up sdk redirect: {}", sdk);
        ENDPOINTS.sdk = Some(sdk.origin().unicode_serialization());
        usesRedirect = true;
    }

    println!("Initializing modules...");
    if let Err(e) = module_manager.enable(MhyContext::<HoYoPass>::new(&exe_name)){
        println!("Error initializing hoyopass, if on 6.0+ this causes login problems: {}", e)
    };

    println!("Waiting for ua");
    while !is_user_assembly_loaded() {
        thread::sleep(Duration::from_millis(10));
    }
    sleep(Duration::from_secs(2));

    let _ = module_manager.enable(MhyContext::<Security>::new(UA_DLL_NAME));

    marshal::find();

    if usesRedirect {
        if let Err(e) = module_manager.enable(MhyContext::<Http>::new(UA_DLL_NAME)){
            println!("Error initializing https module, automatic redirects will not work, use a proxy instead: {}", e)
        };
    }
    let _ = module_manager.enable(MhyContext::<Misc>::new(&exe_name));

    println!("Successfully initialized!");
}

lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}
fn is_user_assembly_loaded() -> bool {
    unsafe { GetModuleHandleA(s!("UserAssembly.dll")).is_ok() }
}

// todo check if mhynot2.dll exists, otherwise don't try to load
unsafe fn loadMhypnot(){
    let libwinpthread = LoadLibraryW(&windows::core::HSTRING::from("libwinpthread-1.dll")).unwrap();
    let mhypnot = LoadLibraryW(&windows::core::HSTRING::from("mhynot2.dll")).unwrap();
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        initConsole();
        loadMhypnot();
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
