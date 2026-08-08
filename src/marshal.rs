use std::ffi::{CStr, CString};
use crate::{il2cpp, util};

use windows::Win32::{System::LibraryLoader::GetModuleFileNameA};
use std::path::Path;
use crate::config::{REG, RUNTIME_CONFIG};
use crate::il2cpp::Il2CppApi;

const PTR_TO_STRING_ANSI: &str = "E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ??";
// static string Marshal.PtrToStringAnsi(IntPtr ptr)
//const PTR_TO_STRING_ANSI: &str = "E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ?? 83 B9 E0 00 00 00 00 75 0C E8 ?? ?? ?? ?? 48 8B 0D F3 ?? ?? ?? 48 8B 81 B8 00 00 00 83 78 04 02";
// E9 6B F1 72 FA CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D 08 67 98 03 83 B9 E0 00 00 00 00 75 0C E8 F2 AF 79 FA 48 8B 0D F3 66 98 03 48 8B 81 B8 00 00 00 83 78 04 02
///
/// 2.7 E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC | E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ?? 83 B9 E0 00 00 00 00 75 0C E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 81 B8 00 00 00 83 78 04 02
/// 2.8 E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC | E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ?? 83 B9 E0 00 00 00 00 75 0C E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 81 B8 00 00 00 83 78 04 02
/// CCCCCCCCCCCCCCCCCCCCCC40534883EC20488BD948
const PTR_TO_STRING_ANSI_OFFSET: usize = 0x0;
type MarshalPtrToStringAnsi1 = unsafe extern "fastcall" fn(*const u8) -> *const u8;
type MarshalPtrToStringAnsi2 = unsafe extern "fastcall" fn(u8, *const u8) -> *const u8;
static mut PTR_TO_STRING_ANSI_ADDR: Option<usize> = None;

pub unsafe fn create_il2cpp_string(content: &str) -> *const u8 {
    if PTR_TO_STRING_ANSI_ADDR.is_none() {
        find(None);
    }

    let text = CString::new(content).unwrap();
    let target_reg = &RUNTIME_CONFIG.get().unwrap().first_arg_register;
    match target_reg {
        REG::RCX => {
            let func = std::mem::transmute::<usize, MarshalPtrToStringAnsi1>(PTR_TO_STRING_ANSI_ADDR.unwrap());
            func(text.as_c_str().to_bytes_with_nul().as_ptr())
        }
        REG::RDX => {
            let func = std::mem::transmute::<usize, MarshalPtrToStringAnsi2>(PTR_TO_STRING_ANSI_ADDR.unwrap());
            func(0, text.as_c_str().to_bytes_with_nul().as_ptr())
        }
        value => {
            panic!("Unsupported value {:?}", value);
        }
    }
}

unsafe fn via_il2cpp_api(il2cpp_api: &Il2CppApi) {
    let ptr_to_string_ansi = il2cpp::find_method_pointer(
        il2cpp_api,
        "mscorlib.dll",
        "System.Runtime.InteropServices",
        "Marshal",
        "PtrToStringAnsi",
        1,
    );
    if let Some(addr) = ptr_to_string_ansi {
        PTR_TO_STRING_ANSI_ADDR = Some(addr as usize);
        println!("[il2cpp]  ptr_to_string_ansi: {:x}", addr as usize);
    }
    else
    {
        println!("[il2cpp]  Failed to find ptr_to_string_ansi");
    }
}

unsafe fn via_pattern(){
    let ptr_to_string_ansi = util::pattern_scan_il2cpp("UserAssembly.dll", PTR_TO_STRING_ANSI);
    if let Some(addr) = ptr_to_string_ansi {
        let addr_offset = addr as usize + PTR_TO_STRING_ANSI_OFFSET;
        PTR_TO_STRING_ANSI_ADDR = Some(addr_offset);
        println!("[pattern] ptr_to_string_ansi: {:x}", addr_offset);
    } else {
        println!("[pattern] Failed to find ptr_to_string_ansi");
    }
}

pub unsafe fn find(il2cpp_api: Option<&Il2CppApi>) {
    match il2cpp_api {
        Some(api) => {
            via_il2cpp_api(api)
        }
        None => {
            via_pattern();
        }
    };
}

unsafe fn module() -> &'static str {
    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    Box::leak(Box::new(Path::new(exe_path).file_name().unwrap().to_str().unwrap().to_string()))
}