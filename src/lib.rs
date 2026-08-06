#![feature(str_from_utf16_endian)]

use std::{fmt, sync::RwLock, thread};

use crate::arguments::parse_parameters;
use crate::config::CONFIG;
use clap::Parser;
use lazy_static::lazy_static;
use modules::{CcpBlocker, Misc};
use std::ffi::CStr;
use std::thread::sleep;
use std::time::Duration;
use std::{
    io::{Read, Seek},
    path::Path,
};
use windows::core::s;
use windows::Win32::System::Console;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryW};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleFileNameA};

mod interceptor;
mod marshal;
mod modules;
mod util;
mod config;
mod version;
mod arguments;
mod logging;

use crate::modules::{HoYoPass, Http, MhyContext, ModuleManager, Security};
use crate::version::{read_game_version, GameVersion};
use crate::logging::{setup_logging};


const UA_DLL_NAME: &str = "UserAssembly.dll";

unsafe fn initConsole(){
    Console::AllocConsole().unwrap();
}

fn print_header(region: REGION, version: GameVersion){
    println!("Legacy Genshin Impact encryption patch\nMade by hartie95\nOriginally by xeondev\ngame version: {version}");
}

unsafe fn getRegionByExe() -> REGION{
    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    let exe_name = Path::new(exe_path).file_name().unwrap().to_str().unwrap();
    println!("Current executable name: {}", exe_name);

    if exe_name == "GenshinImpact.exe"{
        REGION::OS
    } else if exe_name == "YuanShen.exe" {
        REGION::CN
    } else {
        REGION::INVALID
    }
}
enum UAType{
    EXPORTED,
    TABLE_EXPORTED,
    INLINED,
    NONE
}
impl UAType {
    fn toString(&self)->&str{
        match *self {
            UAType::EXPORTED => "EXPORTED",
            UAType::TABLE_EXPORTED => "TABLE_EXPORTED",
            UAType::INLINED => "INLINED",
            UAType::NONE => "NONE",
        }
    }
}

#[cfg(debug_assertions)]
const LOG_LEVEL: tracing::Level = tracing::Level::DEBUG;
#[cfg(not(debug_assertions))]
const LOG_LEVEL: tracing::Level = tracing::Level::INFO;

impl std::fmt::Display for UAType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", match *self {
            UAType::EXPORTED => "EXPORTED",
            UAType::TABLE_EXPORTED => "TABLE_EXPORTED",
            UAType::INLINED => "INLINED",
            UAType::NONE => "NONE",
        } )
    }
}

unsafe fn thread_func(region: REGION, version: GameVersion) {

    let mut module_manager = MODULE_MANAGER.write().unwrap();

    // Block query_security_file ASAP
    let _ = module_manager.enable(MhyContext::<CcpBlocker>::new(""), version);

    if !version.use_mhynot() {
        util::disable_memprotect_guard();
    }

    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    let exe_name = Path::new(exe_path).file_name().unwrap().to_str().unwrap();
    println!("Current executable name: {}", exe_name);

    if exe_name != "GenshinImpact.exe" && exe_name != "YuanShen.exe" {
        println!("Executable is not Genshin. Skipping initialization.");
        return;
    }



    println!("Initializing modules...");
    if let Err(e) = module_manager.enable(MhyContext::<HoYoPass>::new(&exe_name), version){
        println!("Error initializing hoyopass, if on 6.0+ this causes login problems: {}", e)
    };


    if version.has_ua() {
        println!("Waiting for ua");
        while !is_user_assembly_loaded() {
            sleep(Duration::from_millis(10));
        }
        sleep(Duration::from_secs(2));
    }

    let uaType = get_ua_type();
    println!("ua type {uaType}");

    let assembly_name = if version.has_ua() {UA_DLL_NAME} else {exe_name};

    let _ = module_manager.enable(MhyContext::<Security>::new(assembly_name), version);

    marshal::find();

    if CONFIG.usesRedirect {
        if let Err(e) = module_manager.enable(MhyContext::<Http>::new(assembly_name), version){
            println!("Error initializing https module, automatic redirects will not work, use a proxy instead: {}", e)
        };
    }
    let _ = module_manager.enable(MhyContext::<Misc>::new(&exe_name), version);

    println!("Successfully initialized!");
}


#[derive(Clone, Copy)]
enum REGION{
    CN,
    OS,
    INVALID
}

fn get_ua_type() -> UAType {
    if !is_user_assembly_loaded() {
        return UAType::NONE;
    }
    let uaHandle = unsafe { GetModuleHandleA(s!("UserAssembly.dll")) }.unwrap();

    let il2cpp_function_address = unsafe { GetProcAddress(uaHandle, s!("il2cpp_class_get_type")) };
    match il2cpp_function_address {
        Some(addr) => {
            return UAType::EXPORTED;
        }
        None => {
            println!("Export does not exist, 3.2+");
        }
    }
    let il2cpp_table_address = unsafe { GetProcAddress(uaHandle, s!("il2cpp_get_api_table")) };
    match il2cpp_table_address {
        Some(addr) => {
            return UAType::TABLE_EXPORTED;
        }
        None => {
            println!("table export does not exist, 4.3+(?)");
        }
    }

    return UAType::INLINED;
}


lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}
fn is_user_assembly_loaded() -> bool {
    unsafe { GetModuleHandleA(s!("UserAssembly.dll")).is_ok() }
}

fn loadMhypnot(){
    if Path::new("libwinpthread-1.dll").exists() {
        let libwinpthread = unsafe { LoadLibraryW(&windows::core::HSTRING::from("libwinpthread-1.dll")) }.unwrap();
    }
    if Path::new("mhynot2.dll").exists() {
        let mhypnot = unsafe { LoadLibraryW(&windows::core::HSTRING::from("mhynot2.dll")) }.unwrap();
    }
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        parse_parameters();
        initConsole();
        setup_logging();
        let region = getRegionByExe();
        let version = read_game_version(region);
        match version {
            Ok(version) => {
                print_header(region, version);
                if version.use_mhynot(){
                    loadMhypnot();
                }
                #[cfg(debug_assertions)]
                {
                    thread_func(region, version);
                }
                #[cfg(not(debug_assertions))]
                {
                    std::thread::spawn(move || thread_func(region, version));
                }
            }
            version => {}
        }
    }

    true
}
