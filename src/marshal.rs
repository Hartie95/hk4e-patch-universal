use std::ffi::CStr;
use crate::util;

use windows::Win32::{System::LibraryLoader::GetModuleFileNameA};
use std::path::Path;

//const PTR_TO_STRING_ANSI: &str = "E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ??";
const PTR_TO_STRING_ANSI: &str = "E9 BB FF 65 FB CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D 08 37 94 04 83 B9 E0 00 00 00 00 75 0C E8 82 C2 6C FB 48 8B";
///
/// 2.7 E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC | E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ?? 83 B9 E0 00 00 00 00 75 0C E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 81 B8 00 00 00 83 78 04 02
/// 2.8 E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC | E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ?? 83 B9 E0 00 00 00 00 75 0C E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 81 B8 00 00 00 83 78 04 02
/// CCCCCCCCCCCCCCCCCCCCCC40534883EC20488BD948
const PTR_TO_STRING_ANSI_OFFSET: usize = 0x0;
type MarshalPtrToStringAnsi = unsafe extern "fastcall" fn(*const u8) -> *const u8;
static mut PTR_TO_STRING_ANSI_ADDR: Option<usize> = None;

pub unsafe fn ptr_to_string_ansi(content: &CStr) -> *const u8 {
    if PTR_TO_STRING_ANSI_ADDR.is_none() {
        find();
    }

    let func = std::mem::transmute::<usize, MarshalPtrToStringAnsi>(PTR_TO_STRING_ANSI_ADDR.unwrap());
    func(content.to_bytes_with_nul().as_ptr())
}

pub unsafe fn find() {
    let ptr_to_string_ansi = util::pattern_scan_il2cpp("UserAssembly.dll", PTR_TO_STRING_ANSI);
    if let Some(addr) = ptr_to_string_ansi {
        let addr_offset = addr as usize + PTR_TO_STRING_ANSI_OFFSET;
        PTR_TO_STRING_ANSI_ADDR = Some(addr_offset);
        println!("ptr_to_string_ansi: {:x}", addr_offset);
    } else {
        println!("Failed to find ptr_to_string_ansi");
    }
}

unsafe fn module() -> &'static str {
    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    Box::leak(Box::new(Path::new(exe_path).file_name().unwrap().to_str().unwrap().to_string()))
}