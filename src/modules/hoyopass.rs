use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::OnceLock;
use windows::core::s;
use windows::Win32::Networking::WinHttp::WINHTTP_FLAG_SECURE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use crate::config::ENDPOINTS;
use crate::version::GameVersion;

pub struct HoYoPass;

static FLAG_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND_THREAD_RUNNING: AtomicBool = AtomicBool::new(false);

static HOST: OnceLock<Vec<u16>> = OnceLock::new();
/* patch for login done by pmagixc (https://github.com/pmagixc/hk4e-patch-universal/commit/9cf28499e50e9831566ca95487f79e40d22156da) */
impl MhyModule for MhyContext<HoYoPass> {
    unsafe fn init(&mut self, version: GameVersion) -> Result<()> {
        let winhttp = GetModuleHandleA(s!("winhttp.dll"))?;
        let connect = GetProcAddress(winhttp, s!("WinHttpConnect")).unwrap() as usize;
        let openrequest = GetProcAddress(winhttp, s!("WinHttpOpenRequest")).unwrap() as usize;

        self.interceptor.attach(connect, on_connect);
        self.interceptor.attach(openrequest, on_open_request);

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        FLAG_ADDRESS.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn get_module_type(&self) -> ModuleType {
        ModuleType::HoYoPass
    }
}

// todo get port from url, best in initial setup
unsafe extern "win64" fn on_connect(reg: *mut Registers, _: usize) {
    if ENDPOINTS.sdk.is_none() {
        return;
    }
    println!("on_connect");
    let url = if let Some(sdk) = &ENDPOINTS.sdk {
        sdk.to_string()
    } else{
        return;
    };

    /*let host = HOST.get_or_init(|| {
        url.encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    });*/
    let host = HOST.get_or_init(|| {
        "127.0.0.1".encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    });

    (*reg).rdx = host.as_ptr() as u64;
    (*reg).r8 = 8443 as u64;
}

// todo get if https from url
unsafe extern "win64" fn on_open_request(reg: *mut Registers, _: usize) {
    let flags_ptr = ((*reg).rsp + 0x38) as *mut u32;
    *flags_ptr &= !WINHTTP_FLAG_SECURE.0;
}
