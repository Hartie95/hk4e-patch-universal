use std::ffi::CString;

use crate::marshal;

use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;
use crate::version::GameVersion;

//const MHYRSA_PERFORM_CRYPTO_ACTION: &str = "E8 ?? ?? ?? ?? 66 C7 06 30 82";

// bool RSAUtil.RSAVerifyHash(string key, byte[] bytes, byte[] sign) // 2.8 NINPDCGNGHO
const KEY_SIGN_CHECK: &str = "48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 30 48 8B 05 ?? ?? 57 07 48 8B D9 49 8B F0 48 8B EA 4C 8B 88 B8 00 00 00 49 8B 49 18 48 85 C9 0F 85 59 01 00 00 48 8B 05 ?? ?? 57 07 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D 48 8B 00 81 78 18 00 B2 00 00 7E 71 0F 86 57 01 00 00 38 88 20 B2";
// 48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 30 48 8B 05 DA 30 57 07 48 8B D9 49 8B F0 48 8B EA 4C 8B 88 B8 00 00 00 49 8B 49 18 48 85 C9 0F 85 59 01 00 00 48 8B 05 16 84 57 07 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D 48 8B 00 81 78 18 00 B2 00 00 7E 71 0F 86 57 01 00 00 38 88 20 B2
// 48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 30 48 8B 05 ?? ?? 57 07 48 8B D9 49 8B F0 48 8B EA 4C 8B 88 B8 00 00 00 49 8B 49 18 48 85 C9 0F 85 59 01 00 00 48 8B 05 ?? ?? 57 07 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D 48 8B 00 81 78 18 00 B2 00 00 7E 71 0F 86 57 01 00 00 38 88 20 B2


// bool RSAUtil.RSAVerifyData(string key, byte[] bytes, byte[] sign) // 2.8 CAGCMDCHJAO
const VERIFY_DATA: &str = "48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 30 48 8B 05 ?? ?? 57 07 48 8B D9 49 8B F0 48 8B EA 4C 8B 88 B8 00 00 00 49 8B 49 20 48 85 C9 0F 85 51 01 00 00 48 8B 05 ?? ?? 57 07 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D 48 8B 00 81 78 18 53 C7 00 00 7E 71 0F 86 4F 01 00 00 38 88 73 C7";
// 48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 30 48 8B 05 7A 35 57 07 48 8B D9 49 8B F0 48 8B EA 4C 8B 88 B8 00 00 00 49 8B 49 20 48 85 C9 0F 85 51 01 00 00 48 8B 05 B6 88 57 07 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D 48 8B 00 81 78 18 53 C7 00 00 7E 71 0F 86 4F 01 00 00 38 88 73 C7
// 48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 30 48 8B 05 ?? ?? 57 07 48 8B D9 49 8B F0 48 8B EA 4C 8B 88 B8 00 00 00 49 8B 49 20 48 85 C9 0F 85 51 01 00 00 48 8B 05 ?? ?? 57 07 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D 48 8B 00 81 78 18 53 C7 00 00 7E 71 0F 86 4F 01 00 00 38 88 73 C7


//const KEY_SIGN_CHECK: &str = "89 DA ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 48 8B 4C 24 ?? 48 31 E1 E8 ?? ?? ?? ?? 89 D8 48 83 C4 ??";
const KEY_SIGN_CHECK_OFFSET: usize = 0x0;

//const SDK_UTIL_RSA_ENCRYPT: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ? ? ? ? E8 ";
//SDKUtil.RSAEncrypt
const SDK_UTIL_RSA_ENCRYPT: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ?? ?? 31 ?? E8 ?? ?? ?? ?? 33 D2 48 8B C8 48 8B D8 E8 ?? ?? ?? FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9 E8 ?? ?? ?? FF 48 85 C0 74 59 4C 8B 08 48 8B D6";
// 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D 24 59 31 04 E8 3F D7 09 FB 33 D2 48 8B C8 48 8B D8 E8 B2 9E 76 FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9 E8 6B BC B3 FF 48 85 C0 74 59 4C 8B 08 48 8B D6
// 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ?? ?? 31 ?? E8 ?? ?? ?? ?? 33 D2 48 8B C8 48 8B D8 E8 ?? ?? ?? FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9 E8 ?? ?? ?? FF 48 85 C0 74 59 4C 8B 08 48 8B D6

//MiHoYoSDKUtil.RSAEncrypt
const MIHOYO_SDK_UTIL_RSA_ENCRYPT: &str = "48 89 74 24 10 57 48 83 EC 20 48 8B 05 ?? ?? ?? 05 48 8B F9 48 8B F2 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 21 48 8B 00 81 78 18 3F 2F 00 00 0F 8E AD 00 00 00 0F 86 4E 01 00 00 38 88 5F 2F 00 00 0F 95 C0 EB 0D 45 33 C0 BA 3F 2F 00 00 E8 ?? ?? ?? 00 84 C0 0F 84 87 00 00 00 48 8B 05";
// 48 89 74 24 10 57 48 83 EC 20 48 8B 05 EF 99 29 05 48 8B F9 48 8B F2 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 21 48 8B 00 81 78 18 3F 2F 00 00 0F 8E AD 00 00 00 0F 86 4E 01 00 00 38 88 5F 2F 00 00 0F 95 C0 EB 0D 45 33 C0 BA 3F 2F 00 00 E8 AB E4 6C 00 84 C0 0F 84 87 00 00 00 48 8B 05
// 48 89 74 24 10 57 48 83 EC 20 48 8B 05 ?? ?? ?? 05 48 8B F9 48 8B F2 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 21 48 8B 00 81 78 18 3F 2F 00 00 0F 8E AD 00 00 00 0F 86 4E 01 00 00 38 88 5F 2F 00 00 0F 95 C0 EB 0D 45 33 C0 BA 3F 2F 00 00 E8 ?? ?? ?? 00 84 C0 0F 84 87 00 00 00 48 8B 05

// byte[] RSAUtil.RSAEncrypt(string key, byte[] data) // 2.8 ADOFHHIHDEK
const RSA_UTIL_RSA_ENCRYPT: &str = "40 55 41 54 41 55 41 56 41 57 48 81 EC 80 00 00 00 48 8D 6C 24 30 48 C7 45 38 FE FF FF FF 48 89 9D 80 00 00 00 48 89 B5 88 00 00 00 48 89 BD 90 00 00 00 48 8B DA 48 8B F9 45 33 FF 4C 89 7D 08 8B 04 24 48 83 EC 10 4C 8D 74 24 30 4C 89 75 18 41 8B 06 4C 89 75 28 41 83 CD FF 44 89 6D 30 48";

//MoleMole.MoleMoleSecurity.get_publicRSAKey // 2.8 GGIHJMBMMNI
const SECURITY_GET_PUBLIC_RSA_KEY: &str = "48 8B 05 A1 ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D A0 ?? ?? ?? 83 B9 E0 00 00 00 00 75 05 E8 ?? ?? ?? ?? 48 8B 05 8B ?? ?? ?? 48 8B 90 B8 00 00 00 48 8B 4A 28 48 85 C9 0F 85 A5 00 00 00 48 8B 05 60 ?? ?? ?? 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D";
// 48 8B 05 A1 D9 6C 06 C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D A0 35 58 06 83 B9 E0 00 00 00 00 75 05 E8 C2 E4 35 FD 48 8B 05 8B 35 58 06 48 8B 90 B8 00 00 00 48 8B 4A 28 48 85 C9 0F 85 A5 00 00 00 48 8B 05 60 DF 55 06 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D
// 48 8B 05 A1 ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D A0 ?? ?? ?? 83 B9 E0 00 00 00 00 75 05 E8 ?? ?? ?? ?? 48 8B 05 8B ?? ?? ?? 48 8B 90 B8 00 00 00 48 8B 4A 28 48 85 C9 0F 85 A5 00 00 00 48 8B 05 60 ?? ?? ?? 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D

//const SDK_UTIL_RSA_ENCRYPT: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D 24 59 31 04 E8 3F D7 09 FB 33 D2 48 8B C8 48 8B D8 E8 B2 9E 76 FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9";
const KEY_SIZE: usize = 268;
static SERVER_PUBLIC_KEY: &[u8] = include_bytes!("../../server_public_key.bin");
static SDK_PUBLIC_KEY: &str = include_str!("../../sdk_public_key.xml");
static GC_PUBLIC_KEY: &str = include_str!("../../gc_public_key.xml");

pub struct Security;

impl MhyModule for MhyContext<Security> {
    unsafe fn init(&mut self, version: GameVersion) -> Result<()> {

        /*let mhyrsa_perform_crypto_action = util::pattern_scan_code(self.assembly_name, MHYRSA_PERFORM_CRYPTO_ACTION);
        if let Some(addr) = mhyrsa_perform_crypto_action {
            println!("mhyrsa_perform_crypto_action: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_mhy_rsa,
            )?;
        }
        else
        {
            println!("Failed to find mhyrsa_perform_crypto_action");
        }*/

        let key_sign_check = util::pattern_scan_code(self.assembly_name, KEY_SIGN_CHECK);
        if let Some(addr) = key_sign_check {
            let addr_offset = addr as usize + KEY_SIGN_CHECK_OFFSET;
            println!("key_sign_check: {:x}", addr_offset as usize);
            self.interceptor.replace(
                addr_offset as usize,
                verifySucessfull,
            )?;
        }
        else
        {
            println!("Failed to find key_sign_check");
        }

        let rsautil_verify_data = util::pattern_scan_code(self.assembly_name, VERIFY_DATA);
        if let Some(addr) = rsautil_verify_data {
            let addr_offset = addr as usize ;
            println!("key_sign_check: {:x}", addr_offset as usize);
            self.interceptor.replace(
                addr_offset as usize,
                verifySucessfull,
            )?;
        }
        else
        {
            println!("Failed to find key_sign_check");
        }


        let sdk_util_rsa_encrypt = util::pattern_scan_il2cpp(self.assembly_name, SDK_UTIL_RSA_ENCRYPT);
        if let Some(addr) = sdk_util_rsa_encrypt {
            println!("sdk_util_rsa_encrypt: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_sdk_util_rsa_encrypt,
            )?;
        }
        else
        {
            println!("Failed to find sdk_util_rsa_encrypt");
        }
        let mihoyosdk_util_rsa_encrypt = util::pattern_scan_il2cpp(self.assembly_name, MIHOYO_SDK_UTIL_RSA_ENCRYPT);
        if let Some(addr) = mihoyosdk_util_rsa_encrypt {
            println!("mihoyosdk_util_rsa_encrypt: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_sdk_util_rsa_encrypt,
            )?;
        }
        else
        {
            println!("Failed to find mihoyosdk_util_rsa_encrypt");
        }
        let sdk_util_rsa_encrypt = util::pattern_scan_il2cpp(self.assembly_name, RSA_UTIL_RSA_ENCRYPT);
        if let Some(addr) = sdk_util_rsa_encrypt {
            println!("sdk_util_rsa_encrypt: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_rsa_util_rsa_encrypt,
            )?;
        }
        else
        {
            println!("Failed to find sdk_util_rsa_encrypt");
        }
        let security_get_public_rsa_key = util::pattern_scan_il2cpp(self.assembly_name, SECURITY_GET_PUBLIC_RSA_KEY);
        if let Some(addr) = security_get_public_rsa_key {
            println!("security_get_public_rsa_key: {:x}", addr as usize);
            self.interceptor.replace(
                addr as usize,
                on_security_get_public_rsa_key,
            )?;
        }
        else
        {
            println!("Failed to find sdk_util_rsa_encrypt");
        }

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Security
    }
}

unsafe extern "win64" fn after_key_sign_check(reg: *mut Registers, _: usize) {
    println!("key sign check!");
    (*reg).rax = 1
}
unsafe extern "win64" fn verifySucessfull(
    _: *mut Registers,
    _: usize,
    _: usize,
) -> usize {
    1
}

unsafe extern "win64" fn on_mhy_rsa(reg: *mut Registers, _: usize) {
    println!("key: {:X}", *((*reg).r12 as *const u64));
    println!("len: {:X}", (*reg).r8 -3);

    if ((*reg).r8 as usize) - 3 == KEY_SIZE {
        println!("[*] key replaced");

        std::ptr::copy_nonoverlapping(
            SERVER_PUBLIC_KEY.as_ptr(),
            (*reg).r12 as *mut u8,
            SERVER_PUBLIC_KEY.len(),
        );
    }
}

unsafe extern "win64" fn on_sdk_util_rsa_encrypt(reg: *mut Registers, _: usize) {
    /*println!("[*] SDK RSA: key replaced");
    let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let key = String::from_utf16le(slice).unwrap();
    println!("[*] SDK RSA: previous key {key}");*/
    (*reg).rcx =
        marshal::ptr_to_string_ansi(CString::new(SDK_PUBLIC_KEY).unwrap().as_c_str()) as u64;

    /*let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let key = String::from_utf16le(slice).unwrap();
    println!("[*] SDK RSA: new key {key}");*/
}
unsafe extern "win64" fn on_rsa_util_rsa_encrypt(reg: *mut Registers, _: usize) {
    /*println!("[*] SDK RSA: key replaced");
    let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let key = String::from_utf16le(slice).unwrap();
    println!("[*] SDK RSA: previous key {key}");*/
    (*reg).rcx =
        marshal::ptr_to_string_ansi(CString::new(GC_PUBLIC_KEY).unwrap().as_c_str()) as u64;

    /*let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let key = String::from_utf16le(slice).unwrap();
    println!("[*] SDK RSA: new key {key}");*/
}

unsafe extern "win64" fn on_security_get_public_rsa_key(reg: *mut Registers, _: usize, _: usize,) -> usize {
    println!("[*] gc RSA: key replaced");
    let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let key = String::from_utf16le(slice).unwrap();
    println!("[*] gc RSA: previous key {key}");
    (*reg).rcx =
        marshal::ptr_to_string_ansi(CString::new(GC_PUBLIC_KEY).unwrap().as_c_str()) as u64;

    let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let key = String::from_utf16le(slice).unwrap();
    println!("[*] gc RSA: new key {key}");
    (*reg).rcx as usize
}
