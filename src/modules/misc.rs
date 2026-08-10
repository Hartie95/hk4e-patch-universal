use super::{MhyContext, MhyModule, ModuleType, PatternMethodHookInfo};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::il2cpp::Il2CppApi;
use crate::util;
use crate::version::GameVersion;

pub struct Misc;

// Renderer.SetCustomPropertyFloat ?
// TODO what the name of the function thats patched here
const SET_CUSTOM_PROPERTY_FLOAT_50: &str = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 0F 29 74 24 ?? 0F 28 F2 41 0F B6 F9 8B F2 48 8B D9 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 85 C0 74 ?? 40 84 FF 0F 28 D6 8B D6 48 8B C8 41 0F 95 C1 48 8B 5C 24 ?? 48 8B 74 24 ?? 0F 28 74 24 ?? 48 83 C4 ?? 5F E9 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? CC 48 89 5C 24 ?? 57 48 83 EC ?? 8B FA 48 8B D9 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 85 C0 74 ?? 8B D7 48 8B C8 48 8B 5C 24 ?? 48 83 C4 ?? 5F E9 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? CC CC CC CC CC CC 48 89 5C 24";
impl PatternMethodHookInfo {
    // 5.0+
    pub const SET_CUSTOM_PROPERTY_FLOAT_50: Self = Self {
        name: "SET_CUSTOM_PROPERTY_FLOAT_50",
        pattern: SET_CUSTOM_PROPERTY_FLOAT_50,
        offset: 0,
    };
}

impl MhyModule for MhyContext<Misc> {
    unsafe fn init(&mut self, version: GameVersion, il2cpp_api: Option<&Il2CppApi>) -> Result<()> {
        // Dither
        match il2cpp_api {
            Some(api) => {
                self.via_il2cpp(version, api)
            }
            None => {
                self.via_pattern(version)
            }
        }
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Misc
    }
}
impl MhyContext<Misc> {
    unsafe fn via_il2cpp(&mut self, version: GameVersion, il2cpp_api: &Il2CppApi) -> Result<()> {
        Ok(())
    }
    unsafe fn via_pattern(&mut self, version: GameVersion) -> Result<()> {
        if version.is_at_least(4, 7, 50) {
            let _ = self.hook_pattern_replace(PatternMethodHookInfo::SET_CUSTOM_PROPERTY_FLOAT_50, set_custom_property_float_replacement);
            return Ok(())
        }
        Ok(())
    }
    
}



unsafe extern "win64" fn set_custom_property_float_replacement(
    _: *mut Registers,
    _: usize,
    _: usize,
) -> usize {
    0
}
