use std::{fmt, sync::RwLock, thread};

use crate::arguments::parse_parameters;
use lazy_static::lazy_static;
use modules::{CcpBlocker, Misc};
use std::ffi::CStr;
use std::thread::sleep;
use std::time::Duration;
use std::{
    path::Path,
};
use windows::core::s;
use windows::Win32::System::Console;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryW};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleFileNameA};
use crate::config::{init_runtime_config, PATCHER_CONFIG};
use crate::il2cpp::Il2CppApi;

mod interceptor;
mod marshal;
mod modules;
mod util;
mod config;
mod version;
mod arguments;
mod logging;
mod il2cpp;

use crate::modules::{HoYoPass, Http, MhyContext, ModuleManager, Security};
use crate::version::{read_game_version, GameVersion};
use crate::logging::{setup_logging};


const UA_DLL_NAME: &str = "UserAssembly.dll";

#[cfg(debug_assertions)]
const LOG_LEVEL: tracing::Level = tracing::Level::DEBUG;
#[cfg(not(debug_assertions))]
const LOG_LEVEL: tracing::Level = tracing::Level::INFO;

unsafe fn init_console(){
    match Console::AllocConsole() {
        Err(error) => println!("Failed to initialize console: {}", error),
        value => return
    }
}

fn print_header(region: REGION, version: GameVersion){
    println!("Legacy Genshin Impact encryption patch\nMade by hartie95\nOriginally by xeondev\ngame version: {region} {version}");
}

unsafe fn get_region_by_exe() -> REGION{
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

#[derive(PartialEq, Eq)]
enum UAType{
    Exported,
    TableExported,
    Inlined,
    None
}
impl UAType {
    fn to_string(&self)->&str{
        match *self {
            UAType::Exported => "EXPORTED",
            UAType::TableExported => "TABLE_EXPORTED",
            UAType::Inlined => "INLINED",
            UAType::None => "NONE",
        }
    }
}


impl std::fmt::Display for UAType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_string() )
    }
}


#[derive(Clone, Copy)]
enum REGION{
    CN,
    OS,
    INVALID
}
impl REGION {
    fn to_string(&self)->&str{
        match *self {
            REGION::CN => "CN",
            REGION::OS => "OS",
            REGION::INVALID => "INVALID"
        }
    }
}
impl std::fmt::Display for REGION {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

unsafe fn thread_func(region: REGION, version: GameVersion) {
    init_console();
    print_header(region, version);
    parse_parameters();
    setup_logging();

    init_runtime_config(version);

    let mut module_manager = MODULE_MANAGER.write().unwrap();

    // Block query_security_file ASAP
    let _ = module_manager.enable(MhyContext::<CcpBlocker>::new(""), version, None);

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
    if version.is_at_least(5, 8, 50) {
        if let Err(e) = module_manager.enable(MhyContext::<HoYoPass>::new(&exe_name), version, None){
            println!("Error initializing hoyopass, if on 6.0+ this causes login problems: {}", e)
        };
    }


    let mut il2cpp_api: Option<Il2CppApi> = None;
    if version.has_ua() {
        println!("Waiting for ua");
        while !is_user_assembly_loaded() {
            sleep(Duration::from_millis(10));
        }
        sleep(Duration::from_secs(2));

        let user_assembly = GetModuleHandleA(s!("UserAssembly.dll")).unwrap();
        il2cpp_api = Il2CppApi::load(user_assembly)
    }

    let ua_type = get_ua_type();
    println!("ua type {ua_type}");

    let assembly_name = if version.has_ua() {UA_DLL_NAME} else {exe_name};

    let _ = module_manager.enable(MhyContext::<Security>::new(assembly_name), version, il2cpp_api.as_ref());

    marshal::find(il2cpp_api.as_ref());

    if PATCHER_CONFIG.get().unwrap().use_redirects {
        if let Err(e) = module_manager.enable(MhyContext::<Http>::new(assembly_name), version, il2cpp_api.as_ref()){
            println!("Error initializing https module, automatic redirects will not work, use a proxy instead: {}", e)
        };
    }
    let _ = module_manager.enable(MhyContext::<Misc>::new(&exe_name), version, il2cpp_api.as_ref());

    println!("Successfully initialized!");
}



fn get_ua_type() -> UAType {
    if !is_user_assembly_loaded() {
        return UAType::None;
    }
    let ua_handle = unsafe { GetModuleHandleA(s!("UserAssembly.dll")) }.unwrap();

    let il2cpp_function_address = unsafe { GetProcAddress(ua_handle, s!("il2cpp_class_get_type")) };
    match il2cpp_function_address {
        Some(_) => {
            return UAType::Exported;
        }
        None => {
            println!("Export does not exist, 3.2+");
        }
    }
    let il2cpp_table_address = unsafe { GetProcAddress(ua_handle, s!("il2cpp_get_api_table")) };
    match il2cpp_table_address {
        Some(_) => {
            return UAType::TableExported;
        }
        None => {
            println!("table export does not exist, 4.3+(?)");
        }
    }

    UAType::Inlined
}


lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}
fn is_user_assembly_loaded() -> bool {
    unsafe { GetModuleHandleA(s!("UserAssembly.dll")).is_ok() }
}

fn load_mhypnot(){
    if Path::new("libwinpthread-1.dll").exists() {
        let _ = unsafe { LoadLibraryW(&windows::core::HSTRING::from("libwinpthread-1.dll")) }.unwrap();
    }
    if Path::new("mhynot2.dll").exists() {
        let _ = unsafe { LoadLibraryW(&windows::core::HSTRING::from("mhynot2.dll")) }.unwrap();
    }
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        let region = get_region_by_exe();
        let version = read_game_version(region);
        match version {
            Ok(version) => {
                if version.use_mhynot(){
                    load_mhypnot();
                }
                thread::spawn(move || thread_func(region, version));
            }
            Err(error) => {
                init_console();
                println!("failed to identify game region {region} or version: {error}");
            }
        }
    }

    true
}
