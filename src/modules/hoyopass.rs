use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};

pub struct HoYoPass;

const LOGIN_MANAGER_INITIALIZE: &str = "56 57 53 48 83 EC ?? 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 48";

const HOYOPASS_SDK_INITIALIZE: &str = "55 56 57 48 83 EC ?? 48 8D 6C 24 ?? 48 C7 45 ?? ?? ?? ?? ?? 48 89 CE 80 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 80 B9 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48 89 F1 E8 ?? ?? ?? ?? 48 89 C6";

const HOYOPASS_ENABLE_FLAG_OFFSET: usize = 65;

static FLAG_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND_THREAD_RUNNING: AtomicBool = AtomicBool::new(false);

/* patch for login done by pmagixc (https://github.com/pmagixc/hk4e-patch-universal/commit/9cf28499e50e9831566ca95487f79e40d22156da) */
impl MhyModule for MhyContext<HoYoPass> {
    unsafe fn init(&mut self) -> Result<()> {
        
        let mut success = false;
        
        let login_manager_initialize = util::pattern_scan_il2cpp(self.assembly_name, LOGIN_MANAGER_INITIALIZE);
        
        if let Some(addr) = login_manager_initialize {
            println!("hoyopass_loginmanager_initialize: {:x}", addr as usize);
            
            self.interceptor.attach(
                addr as usize,
                on_login_manager_initialize,
            )?;
            
            success = true;
            
            if !BACKGROUND_THREAD_RUNNING.swap(true, Ordering::Relaxed) {
                std::thread::spawn(|| {
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        
                        let flag_addr = FLAG_ADDRESS.load(Ordering::Relaxed);
                        if flag_addr != 0 {
                            unsafe {
                                std::ptr::write_volatile(flag_addr as *mut u8, 0u8);
                            }
                        }
                    }
                });
            }
            
        } else {
            println!("failed to obtain pattern");
        }
        
        let sdk_initialize = util::pattern_scan_il2cpp(self.assembly_name, HOYOPASS_SDK_INITIALIZE);
        
        if let Some(addr) = sdk_initialize {
            println!("hoyopass_sdk_initialize: {:x}", addr as usize);
            
            self.interceptor.replace(
                addr as usize,
                on_hoyopass_sdk_initialize_replacement,
            )?;
            
            println!("forced return 0 on sdk");
            success = true;
        } else {
            println!("failed to obtain sdk pattern");
        }
        
        if !success {
            return Err(anyhow::anyhow!("failed to obtain any pattern"));
        }

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

unsafe extern "win64" fn on_login_manager_initialize(reg: *mut Registers, _: usize) {
    let this_ptr = (*reg).rcx as *mut u8;
    let flag_addr = this_ptr.add(HOYOPASS_ENABLE_FLAG_OFFSET);
    
    FLAG_ADDRESS.store(flag_addr as usize, Ordering::Relaxed);

    std::ptr::write_volatile(flag_addr, 0u8);
    
    println!("disabled hoyopass flag at +{} ({:x})", 
             HOYOPASS_ENABLE_FLAG_OFFSET, flag_addr as usize);
}

unsafe extern "win64" fn on_hoyopass_sdk_initialize_replacement(
    _reg: *mut Registers,
    _: usize,
    _: usize,
) -> usize {
    println!("force success on sdk init");
    0
}
