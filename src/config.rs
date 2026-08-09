use std::sync::OnceLock;
use ilhook::x64::Registers;
use crate::version::GameVersion;

pub static PATCHER_CONFIG: OnceLock<AppConfig> = OnceLock::new();
pub static RUNTIME_CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();

// general patcher config

// todo store uri for hoyopass use?
#[derive(Debug)]
pub struct RedirectConfig {
    pub dispatch: Option<String>,
    pub sdk: Option<String>,
}

#[derive(Debug)]
pub struct EncryptionConfig {
    pub sdk_key: String,
    pub signing_key: String,
    pub encryption_key: String,
}
#[derive(Debug)]
pub struct LogConfig {
    pub file_logging: bool,
    pub log_connections: bool,
    pub log_crypto_keys: bool,
}

#[derive(Debug)]
pub struct AppConfig {
    pub use_redirects: bool,
    pub log_config: LogConfig,
    pub redirect_config: RedirectConfig,
    pub encryption_config: EncryptionConfig,
}
impl Default for AppConfig {
    fn default() -> Self {
        Self {
            use_redirects: false,
            log_config: LogConfig{
                file_logging: cfg!(debug_assertions),
                log_connections: cfg!(debug_assertions),
                log_crypto_keys: cfg!(debug_assertions),

            },
            redirect_config: RedirectConfig {
                dispatch: None,
                sdk: None
            },
            encryption_config: EncryptionConfig {
                sdk_key: include_str!("../sdk_public_key.xml").to_string(),
                signing_key: include_str!("../gc_signing.pem").to_string(),
                encryption_key: include_str!("../gc_signing.pem").to_string()
            }
        }
    }
}


// Runtime config thats version dependent

#[derive(Debug)]
pub enum REG{
    RCX,
    RDX,
    R8,
    R9,
}
impl REG {
    pub unsafe fn set_register(&self, reg: *mut Registers, value: u64){
        match self {
            REG::RCX => (*reg).rcx = value,
            REG::RDX => (*reg).rdx = value,
            REG::R8 => (*reg).r8 = value,
            REG::R9 => (*reg).r9 = value
        }
    }
    pub unsafe fn read_register(&self, reg: *mut Registers) -> u64{
        match self {
            REG::RCX => (*reg).rcx,
            REG::RDX => (*reg).rdx,
            REG::R8 => (*reg).r8,
            REG::R9 => (*reg).r9
        }
    }
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub first_arg_register: REG,
}

impl RuntimeConfig {
    pub const PRE_2_7: Self = Self {
        first_arg_register: REG::RDX,
    };

    pub const DEFAULT_CONFIG: Self = Self {
        first_arg_register: REG::RCX,
    };
}

// todo verify exact version between 2.4 and 2.7 that changed
pub fn init_runtime_config(version: GameVersion){
    let mut target: RuntimeConfig = RuntimeConfig::DEFAULT_CONFIG;
    if version.is_before(2, 6, 50){
        println!("use old runtime config");
        target =  RuntimeConfig::PRE_2_7
    }
    RUNTIME_CONFIG.set(target).unwrap();
}




