use super::{MhyContext, MhyModule, ModuleType};
use crate::{il2cpp, marshal};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;

//const WEB_REQUEST_UTILS_MAKE_INITIAL_URL: &str = "4C ? ? FA CC E8 46 ? ? FA CC E8 40 ? ? FA CC E8 3A ? ? FA CC E8 34 ? ? FA CC E8 2E ? ? FA CC E8 28 ? ? FA CC CC CC CC CC CC CC CC 48 89";
//WebRequestUtils.MakeInitialUrl(string targetUrl, string localUrl)
// UnityEngine.UnityWebRequestModule.dll
// UnityEngine.UnityWebRequestModule
// UnityEngineInternal
// WebRequestUtils
// MakeInitialUrl

const WEB_REQUEST_UTILS_MAKE_INITIAL_URL: &str = "48 89 4C 24 08 55 53 56 57 41 56 48 83 EC 60 48 8D 6C 24 20 48 C7 45 20 FE FF FF FF 48 8B DA 48 8B F9 8B 04 24 48 83 EC 10 8B 04 24 40 32 F6 40 88 75 78 48 8B 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B F0 48 89 45 08 45 33 C0 48 8B D3 48 8B C8 E8";
//const WEB_REQUEST_UTILS_MAKE_INITIAL_URL: &str = "48 89 4C 24 08 55 53 56 57 41 56 48 83 EC ?? 48 8D 6C 24 20 48 C7 45 00 FE FF FF FF 48 8B";
//4C ? ? FA CC E8 46 ? ? FA CC E8 40 ? ? FA CC E8 3A ? ? FA CC E8 34 ? ? FA CC E8 2E ? ? FA CC E8 28 ? ? FA CC CC CC CC CC CC CC CC | 48 89 4C 24 08 55 53 56 57 41 56 48 83 EC 60 48 8D 6C 24 20 48 C7 45 20 FE FF FF FF 48 8B DA 48 8B F9 8B 04 24 48 83 EC 10 8B 04 24 40 32 F6 40
//4C ? ? FA CC E8 46 ? ? FA CC E8 40 ? ? FA CC E8 3A ? ? FA CC E8 34 ? ? FA CC E8 2E ? ? FA CC E8 28 ? ? FA CC CC CC CC CC CC CC CC | 48 89 4C 24 08 55 53 56 57 41 56 48 83 EC 60 48 8D 6C 24 20 48 C7 45 20 FE FF FF FF 48 8B DA 48 8B F9 8B 04 24 48 83 EC 10 8B 04 24 40 32 F6 40
//                                                                                                                                  | 48 89 4C 24 08 55 53 56 57 41 56 48 83 EC ?? 48 8D 6C 24 20 48 C7 45 00 FE FF FF FF 48 8B D9 33
// 48894C240855535657415648
// MiHoYoSDKDll.web_load_url
const BROWSER_LOAD_URL: &str = "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 33 D2 48 8B 0D ?? ?? 61 ?? E8 ?? ?? 0F 00 48 8B D8 48 85 C0 74 25 45 33 C0 48 8B D7 48 8B C8 E8 ?? ?? 0F 00 33 D2 48 8B CB E8 ?? ?? 0F 00 33 C0 48 8B 5C";
//const BROWSER_LOAD_URL: &str = "41 B0 01 E9 08 00 00 00 0F 1F 84 00 00 00 00 00 56 57";

// D6 E8 8A 2F 00 00 EB DE E8 33 F2 04 FB CC E8 2D F2 04 FB CC E8 27 F2 04 FB CC CC CC CC CC CC CC | 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48 8B F9 41 0F B6 E8 48 8B 0D 3E 29 2D 04 48 8B F2 E8 B6 F1 04 FB 33 D2 48 8B C8 48
// 48 8B 49 08 45 33 C0 BA D1 A6 00 00 48 8B 09 E9 2C 7E 24 06 CC CC CC CC CC CC CC CC CC CC CC CC | 48 8B 49 08 45 33 C0 BA C1 3D 00 00 48 8B 09 E9 0C 7E 24 06 CC CC CC CC CC CC CC CC CC CC CC CC 48 8B 49 08 45 33 C0 BA 32 41 00 00 48 8B 09 E9
const BROWSER_LOAD_URL_OFFSET: usize = 0x0;
//const BROWSER_LOAD_URL_OFFSET: usize = 0x10;

use crate::config::{PATCHER_CONFIG, RUNTIME_CONFIG};
use crate::il2cpp::Il2CppApi;
use crate::version::GameVersion;

pub struct Http;


impl MhyModule for MhyContext<Http> {
    unsafe fn init(&mut self,  version: GameVersion, il2cpp_api: Option<&Il2CppApi>) -> Result<()> {
        match il2cpp_api {
            Some(api) => {
                self.via_il2cpp(version, api)
            }
            None => {
                self.via_pattern()
            }
        }
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Http
    }
}

impl MhyContext<Http> {
    unsafe fn via_il2cpp(&mut self, version: GameVersion, il2cpp_api: &Il2CppApi) -> Result<()>{
        let web_request_utils_make_initial_url = il2cpp::find_method_pointer(
            il2cpp_api,
            "UnityEngine.UnityWebRequestModule.dll",
            "UnityEngineInternal",
            "WebRequestUtils",
            "MakeInitialUrl",
            2,
        );
        if let Some(addr) = web_request_utils_make_initial_url {
            println!("[il2cpp]  web_request_utils_make_initial_url: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_make_initial_url,
            )?;
        }
        else
        {
            println!("[il2cpp]  Failed to find web_request_utils_make_initial_url");
        }


        let assembly_name_browser_load = if version.is_before(2, 7, 50) {
            "Assembly-CSharp-firstpass.dll"
        } else {
            "MiHoYoSDK.dll"
        };
        let namespace_browser_load = if version.is_before(2, 7, 50) {
            "MiHoYo.SDK"
        } else {
            "MiHoYo.SDK.Win"
        };

        let browser_load_url = il2cpp::find_method_pointer(
            il2cpp_api,
            assembly_name_browser_load,
            namespace_browser_load,
            "MiHoYoSDKDll",
            "web_load_url",
            1,
        );
        if let Some(addr) = browser_load_url {
            println!("[il2cpp]  browser_load_url: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_browser_load_url,
            )?;
        }
        else
        {
            println!("[il2cpp]  Failed to find browser_load_url");
        }


        Ok(())
    }
    unsafe fn via_pattern(&mut self) -> Result<()> {
        let web_request_utils_make_initial_url = util::pattern_scan_il2cpp(self.assembly_name, WEB_REQUEST_UTILS_MAKE_INITIAL_URL);
        if let Some(addr) = web_request_utils_make_initial_url {
            println!("[pattern] web_request_utils_make_initial_url: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_make_initial_url,
            )?;
        }
        else
        {
            println!("[pattern] Failed to find web_request_utils_make_initial_url");
        }
        
        let browser_load_url = util::pattern_scan_il2cpp(self.assembly_name, BROWSER_LOAD_URL);
        if let Some(addr) = browser_load_url {
            let addr_offset = addr as usize + BROWSER_LOAD_URL_OFFSET;
            println!("browser_load_url: {:x}", addr_offset);
            self.interceptor.attach(
                addr_offset,
                on_browser_load_url,
            )?;
        }
        else
        {
            println!("Failed to find browser_load_url");
        }

        Ok(())
    }
}

unsafe extern "win64" fn on_make_initial_url(reg: *mut Registers, _: usize) {
    let redirect_config = &PATCHER_CONFIG.get().unwrap().redirect_config;
    if redirect_config.dispatch.is_none() && redirect_config.sdk.is_none() {
        return;
    }

    let log = PATCHER_CONFIG.get().unwrap().log_config.log_connections;
    let arg_target = &RUNTIME_CONFIG.get().unwrap().first_arg_register;

    let base: u64 = arg_target.read_register(reg);

    if base == 0 {
        println!("null pointer in rcx and rdx");
        return;
    }

    let str_length = *(base.wrapping_add(16) as *const u32);
    let str_ptr = base.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let url = String::from_utf16le(slice).unwrap();

    if url.starts_with("file://") {
        return;
    }

    let mut new_url = if url.contains("/query_region_list") {
        if let Some(dispatch) = &redirect_config.dispatch {
            dispatch.to_string()
        } else{
            return;
        }
    } else {
        if let Some(sdk) = &redirect_config.sdk {
            sdk.to_string()
        } else{
            return;
        }
    };

    url.split('/').skip(3).for_each(|s| {
        new_url.push_str("/");
        new_url.push_str(s);
    });

    if !url.contains("/query_cur_region") {
        if log {
            println!("Redirect: {url} -> {new_url}");
        }
        let result = marshal::create_il2cpp_string(new_url.as_str()) as u64;
        arg_target.set_register(reg, result);
    }
}

unsafe extern "win64" fn on_browser_load_url(reg: *mut Registers, _: usize) {
    let redirect_config = &PATCHER_CONFIG.get().unwrap().redirect_config;
    if redirect_config.sdk.is_none() {
        return;
    }
    let log = PATCHER_CONFIG.get().unwrap().log_config.log_connections;
    let str_length = *((*reg).rdx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rdx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let url = String::from_utf16le(slice).unwrap();

    let mut new_url = String::from(redirect_config.sdk.as_ref().unwrap().to_string());
    url.split('/').skip(3).for_each(|s| {
        new_url.push_str("/");
        new_url.push_str(s);
    });

    if log {
        println!("Browser::LoadURL: {url} -> {new_url}");
    }

    (*reg).rdx = marshal::create_il2cpp_string(new_url.as_str()) as u64;
}
