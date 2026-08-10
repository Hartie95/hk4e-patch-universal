use std::collections::HashMap;
use anyhow::{bail, Result};
use ilhook::x64::{JmpBackRoutine, RetnRoutine};
use crate::interceptor::Interceptor;

mod ccp_blocker;
mod hoyopass;
mod http;
mod misc;
mod security;

pub use ccp_blocker::CcpBlocker;
pub use hoyopass::HoYoPass;
pub use http::Http;
pub use misc::Misc;
pub use security::Security;
use crate::{il2cpp, util};
use crate::il2cpp::{Il2CppApi};
use crate::version::GameVersion;

#[derive(Default)]
pub struct ModuleManager {
    modules: HashMap<ModuleType, Box<dyn MhyModule>>,
}
unsafe impl Sync for ModuleManager {}
unsafe impl Send for ModuleManager {}

impl ModuleManager {
    pub unsafe fn enable(&mut self, module: impl MhyModule + 'static, version: GameVersion, il2cpp_api: Option<&Il2CppApi>) -> Result<()> {
        let mut boxed_module = Box::new(module);
        let init_result = boxed_module.init(version, il2cpp_api);
        if init_result.is_err() {
            return init_result
        }

        self.modules
            .insert(boxed_module.get_module_type(), boxed_module);
        Ok(())
    }

    #[allow(dead_code)]
    pub unsafe fn disable(&mut self, module_type: ModuleType) {
        let module = self.modules.remove(&module_type);
        if let Some(mut module) = module {
            module.as_mut().de_init().unwrap();
        }
    }
}

pub struct Il2cppMethodHookInfo {
    pub name: &'static str,
    pub assembly_name: &'static str,
    pub namespace: &'static str,
    pub class_name: &'static str,
    pub method_name: &'static str,
    pub argument_count: i32,
}
pub struct PatternMethodHookInfo {
    pub name: &'static str,
    pub pattern: &'static str,
    pub offset: usize,
}

#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub enum ModuleType {
    Http,
    Security,
    Misc,
    CcpBlocker,
    HoYoPass,
}

pub trait MhyModule {
    unsafe fn init(&mut self, version: GameVersion, il2cpp_api: Option<&Il2CppApi>) -> Result<()>;
    unsafe fn de_init(&mut self) -> Result<()>;
    fn get_module_type(&self) -> ModuleType;
}

pub struct MhyContext<T> {
    pub assembly_name: &'static str,
    pub interceptor: Interceptor,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> MhyContext<T> {
    pub const fn new(assembly_name: &'static str) -> Self {
        Self {
            assembly_name,
            interceptor: Interceptor::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub unsafe fn hook_il2cpp_attach(&mut self, il2cpp_api: &Il2CppApi, method_info: Il2cppMethodHookInfo, routine: JmpBackRoutine) -> Result<()>{
        let web_request_utils_make_initial_url = il2cpp::find_method_pointer(
            il2cpp_api,
            method_info.assembly_name,
            method_info.namespace,
            method_info.class_name,
            method_info.method_name,
            method_info.argument_count,
        );
        if let Some(addr) = web_request_utils_make_initial_url {
            println!("[il2cpp]  {}: {:x}", method_info.name, addr as usize);
            self.interceptor.attach(
                addr as usize,
                routine,
            )?;
            Ok(())
        }
        else
        {
            println!("[il2cpp]  Failed to find {}", method_info.name);
            bail!("Failed to find method")
        }
    }
    pub unsafe fn hook_il2cpp_replace(&mut self, il2cpp_api: &Il2CppApi, method_info: Il2cppMethodHookInfo, routine: RetnRoutine) -> Result<()>{
        let web_request_utils_make_initial_url = il2cpp::find_method_pointer(
            il2cpp_api,
            method_info.assembly_name,
            method_info.namespace,
            method_info.class_name,
            method_info.method_name,
            method_info.argument_count,
        );
        if let Some(addr) = web_request_utils_make_initial_url {
            println!("[il2cpp]  {}: {:x}", method_info.name, addr as usize);
            self.interceptor.replace(
                addr as usize,
                routine,
            )?;
            Ok(())
        }
        else
        {
            println!("[il2cpp]  Failed to find {}", method_info.name);
            bail!("Failed to find method")
        }
    }

    pub unsafe fn hook_pattern_attach(&mut self, method_info: PatternMethodHookInfo, routine: JmpBackRoutine) -> Result<()>{
        let web_request_utils_make_initial_url = util::pattern_scan_il2cpp(self.assembly_name, method_info.pattern);
        match web_request_utils_make_initial_url {
            Some(addr) => {
                println!("[pattern]  {}: {:x}", method_info.name, addr as usize);
                self.interceptor.attach(
                    addr as usize,
                    routine,
                )?;
                Ok(())
            }
            None => {
                println!("[pattern]  Failed to find {}", method_info.name);
                bail!("Failed to find method")
            }
        }
    }

    pub unsafe fn hook_pattern_replace(&mut self, method_info: PatternMethodHookInfo, routine: RetnRoutine) -> Result<()>{
        let web_request_utils_make_initial_url = util::pattern_scan_il2cpp(self.assembly_name, method_info.pattern);
        match web_request_utils_make_initial_url {
            Some(addr) => {
                println!("[pattern]  {}: {:x}", method_info.name, addr as usize);
                self.interceptor.replace(
                    addr as usize,
                    routine,
                )?;
                Ok(())
            }
            None => {
                println!("[pattern]  Failed to find {}", method_info.name);
                bail!("Failed to find method")
            }
        }
    }
}
