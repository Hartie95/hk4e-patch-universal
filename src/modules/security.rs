use crate::{marshal};

use super::{Il2cppMethodHookInfo, MhyContext, MhyModule, ModuleType, PatternMethodHookInfo};
use anyhow::Result;
use ilhook::x64::Registers;
use lazy_static::lazy_static;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use crate::config::{PATCHER_CONFIG, REG, RUNTIME_CONFIG};
use crate::il2cpp::Il2CppApi;
use crate::util;
use crate::version::GameVersion;

// todo struct for version specific il2cpp/patterns, so that version checks can be reduced
// todo clean up
const MHYRSA_PERFORM_CRYPTO_ACTION: &str = "E8 ?? ?? ?? ?? 66 C7 06 30 82";

//const SDK_UTIL_RSA_ENCRYPT: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ? ? ? ? E8 ";
//SDKUtil.RSAEncrypt
const SDK_UTIL_RSA_ENCRYPT: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ?? ?? 31 ?? E8 ?? ?? ?? ?? 33 D2 48 8B C8 48 8B D8 E8 ?? ?? ?? FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9 E8 ?? ?? ?? FF 48 85 C0 74 59 4C 8B 08 48 8B D6";
// 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D 24 59 31 04 E8 3F D7 09 FB 33 D2 48 8B C8 48 8B D8 E8 B2 9E 76 FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9 E8 6B BC B3 FF 48 85 C0 74 59 4C 8B 08 48 8B D6
// 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ?? ?? 31 ?? E8 ?? ?? ?? ?? 33 D2 48 8B C8 48 8B D8 E8 ?? ?? ?? FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9 E8 ?? ?? ?? FF 48 85 C0 74 59 4C 8B 08 48 8B D6

//MiHoYoSDKUtil.RSAEncrypt
const MIHOYO_SDK_UTIL_RSA_ENCRYPT: &str = "48 89 74 24 10 57 48 83 EC 20 48 8B 05 ?? ?? ?? 05 48 8B F9 48 8B F2 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 21 48 8B 00 81 78 18 3F 2F 00 00 0F 8E AD 00 00 00 0F 86 4E 01 00 00 38 88 5F 2F 00 00 0F 95 C0 EB 0D 45 33 C0 BA 3F 2F 00 00 E8 ?? ?? ?? 00 84 C0 0F 84 87 00 00 00 48 8B 05";
// 48 89 74 24 10 57 48 83 EC 20 48 8B 05 EF 99 29 05 48 8B F9 48 8B F2 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 21 48 8B 00 81 78 18 3F 2F 00 00 0F 8E AD 00 00 00 0F 86 4E 01 00 00 38 88 5F 2F 00 00 0F 95 C0 EB 0D 45 33 C0 BA 3F 2F 00 00 E8 AB E4 6C 00 84 C0 0F 84 87 00 00 00 48 8B 05
// 48 89 74 24 10 57 48 83 EC 20 48 8B 05 ?? ?? ?? 05 48 8B F9 48 8B F2 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 21 48 8B 00 81 78 18 3F 2F 00 00 0F 8E AD 00 00 00 0F 86 4E 01 00 00 38 88 5F 2F 00 00 0F 95 C0 EB 0D 45 33 C0 BA 3F 2F 00 00 E8 ?? ?? ?? 00 84 C0 0F 84 87 00 00 00 48 8B 05

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


// byte[] RSAUtil.RSAEncrypt(string key, byte[] data) // 2.8 ADOFHHIHDEK
const RSA_UTIL_RSA_ENCRYPT: &str = "40 55 41 54 41 55 41 56 41 57 48 81 EC 80 00 00 00 48 8D 6C 24 30 48 C7 45 38 FE FF FF FF 48 89 9D 80 00 00 00 48 89 B5 88 00 00 00 48 89 BD 90 00 00 00 48 8B DA 48 8B F9 45 33 FF 4C 89 7D 08 8B 04 24 48 83 EC 10 4C 8D 74 24 30 4C 89 75 18 41 8B 06 4C 89 75 28 41 83 CD FF 44 89 6D 30 48";

//MoleMole.MoleMoleSecurity.get_publicRSAKey // 2.8 GGIHJMBMMNI
const SECURITY_GET_PUBLIC_RSA_KEY: &str = "48 8B 05 A1 ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D A0 ?? ?? ?? 83 B9 E0 00 00 00 00 75 05 E8 ?? ?? ?? ?? 48 8B 05 8B ?? ?? ?? 48 8B 90 B8 00 00 00 48 8B 4A 28 48 85 C9 0F 85 A5 00 00 00 48 8B 05 60 ?? ?? ?? 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D";
// 48 8B 05 A1 D9 6C 06 C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D A0 35 58 06 83 B9 E0 00 00 00 00 75 05 E8 C2 E4 35 FD 48 8B 05 8B 35 58 06 48 8B 90 B8 00 00 00 48 8B 4A 28 48 85 C9 0F 85 A5 00 00 00 48 8B 05 60 DF 55 06 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D
// 48 8B 05 A1 ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D A0 ?? ?? ?? 83 B9 E0 00 00 00 00 75 05 E8 ?? ?? ?? ?? 48 8B 05 8B ?? ?? ?? 48 8B 90 B8 00 00 00 48 8B 4A 28 48 85 C9 0F 85 A5 00 00 00 48 8B 05 60 ?? ?? ?? 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D

//const SDK_UTIL_RSA_ENCRYPT: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D 24 59 31 04 E8 3F D7 09 FB 33 D2 48 8B C8 48 8B D8 E8 B2 9E 76 FF 48 85 DB 0F 84 82 00 00 00 4C 8B 0B 48 8B D7 48 8B CB 4D 8B 81 B8 01 00 00 41 FF 91 B0 01 00 00 33 C9";

const SDK_UTIL_RSA_ENCRYPT_32: &str = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B F2 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 48 85 DB 74 7B";
const SECURITY_GET_PUBLIC_RSA_KEY_32: &str = "48 8B 05 A1 ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 48 8B D9 48 8B 0D A0 ?? ?? ?? 83 B9 E0 00 00 00 00 75 05 E8 ?? ?? ?? ?? 48 8B 05 8B ?? ?? ?? 48 8B 90 B8 00 00 00 48 8B 4A 28 48 85 C9 0F 85 A5 00 00 00 48 8B 05 60 ?? ?? ?? 48 8B 80 B8 00 00 00 48 8B 48 10 48 85 C9 75 1D";

                                     //48 BA 45 78 70 6F 6E 65 6E 74 48 89 90 ? ? ? ? 48 BA 3E 3C 2F 52 53 41 4B 65
const MHYRSA_PERFORM_CRYPTO_ACTION_50: &str = "E8 ?? ?? ?? ?? 66 C7 06 30 82";
const KEY_SIGN_CHECK_50: &str = "89 DA ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 48 8B 4C 24 ?? 48 31 E1 E8 ?? ?? ?? ?? 89 D8 48 83 C4 ??";
const KEY_SIGN_CHECK_OFFSET_50: usize = 0x22;
const SDK_UTIL_RSA_ENCRYPT_50: &str = "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC ?? 49 89 D6 48 89 CE 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 C5";


const MHYRSA_PERFORM_CRYPTO_ACTION_65: &str = "E8 ?? ?? ?? ?? 48 83 C4 20 66 41 C7 06 30 82";
const KEY_SIGN_CHECK_65: &str = "E8 ?? ?? ?? ?? 48 83 C4 30 84 C0 74 ?? 41 8B 04 24";
const KEY_SIGN_CHECK_OFFSET_65: usize = 0x5;


const KEY_SIZE: usize = 268;


impl Il2cppMethodHookInfo {
    // SDKUtil.RSAEncrypt
    pub const SDK_UTIL_RSA_ENCRYPT: Self = Self {
        name: "SDK_UTIL_RSA_ENCRYPT",
        assembly_name: "MiHoYoSDK.dll",
        namespace: "MiHoYo.SDK",
        class_name: "SDKUtil",
        method_name: "RSAEncrypt",
        argument_count: 2,
    };


    // MiHoYoSDKUtil.RSAEncrypt
    pub const MIHOYO_SDK_UTIL_RSA_ENCRYPT: Self = Self {
        name: "MIHOYO_SDK_UTIL_RSA_ENCRYPT",
        assembly_name: "Assembly-CSharp-firstpass.dll",
        namespace: "MiHoYo.SDK",
        class_name: "MiHoYoSDKUtil",
        method_name: "RSAEncrypt",
        argument_count: 2,
    };


    // RSAUtil.RSAEncrypt
    pub const RSA_UTIL_RSA_ENCRYPT_28: Self = Self {
        name: "RSA_UTIL_RSA_ENCRYPT_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HIGDKPFEPDM",
        method_name: "ADOFHHIHDEK",
        argument_count: 2,
    };
    pub const RSA_UTIL_RSA_ENCRYPT_30: Self = Self {
        name: "RSA_UTIL_RSA_ENCRYPT_30",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "CFHNOJNNPJM",
        method_name: "COHLKBFJAHK",
        argument_count: 2,
    };
    pub const RSA_UTIL_RSA_ENCRYPT_31: Self = Self {
        name: "RSA_UTIL_RSA_ENCRYPT_31",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "PKFIJILJAND",
        method_name: "CDBOCMBCNJC",
        argument_count: 2,
    };


    // RSAUtil.RSAVerifyHash
    pub const RSA_UTIL_VERIFY_HASH_28: Self = Self {
        name: "RSA_UTIL_VERIFY_HASH_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HIGDKPFEPDM",
        method_name: "NINPDCGNGHO",
        argument_count: 3,
    };

    pub const RSA_UTIL_VERIFY_HASH_30: Self = Self {
        name: "RSA_UTIL_VERIFY_HASH_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HIGDKPFEPDM",
        method_name: "KMPGECCPAJM",
        argument_count: 3,
    };

    pub const RSA_UTIL_VERIFY_HASH_31: Self = Self {
        name: "RSA_UTIL_VERIFY_HASH_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HIGDKPFEPDM",
        method_name: "PDLKKENNJLM",
        argument_count: 3,
    };


    // RSAUtil.RSAVerifyData
    pub const RSA_UTIL_VERIFY_DATA_28: Self = Self {
        name: "RSA_UTIL_VERIFY_DATA_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HIGDKPFEPDM",
        method_name: "CAGCMDCHJAO",
        argument_count: 3,
    };
    pub const RSA_UTIL_VERIFY_DATA_30: Self = Self {
        name: "RSA_UTIL_VERIFY_DATA_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HIGDKPFEPDM",
        method_name: "HBMMACNNAIB",
        argument_count: 3,
    };
    pub const RSA_UTIL_VERIFY_DATA_31: Self = Self {
        name: "RSA_UTIL_VERIFY_DATA_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HIGDKPFEPDM",
        method_name: "GODDCNANDHK",
        argument_count: 3,
    };


    // MoleMoleSecurity.get_publicRSAKey
    pub const SECURITY_GET_PUBLIC_KEY_28: Self = Self {
        name: "SECURITY_GET_PUBLIC_KEY_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "HGMCNHFMMON",
        method_name: "GGIHJMBMMNI",
        argument_count: 0,
    };
    pub const SECURITY_GET_PUBLIC_KEY_30: Self = Self {
        name: "SECURITY_GET_PUBLIC_KEY_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "LNLLCGKMMMB",
        method_name: "FIMLGACKHNC",
        argument_count: 0,
    };
    pub const SECURITY_GET_PUBLIC_KEY_31: Self = Self {
        name: "SECURITY_GET_PUBLIC_KEY_28",
        assembly_name: "Assembly-CSharp.dll",
        namespace: "",
        class_name: "FCHAFLOIDCC",
        method_name: "CPIIJALEPEJ",
        argument_count: 0,
    };
}

impl PatternMethodHookInfo {
    // 50+ offsets
    pub const MHYRSA_PERFORM_CRYPTO_ACTION_50: Self = Self {
        name: "MHYRSA_PERFORM_CRYPTO_ACTION_50",
        pattern: MHYRSA_PERFORM_CRYPTO_ACTION_50,
        offset: 0,
    };

    pub const KEY_SIGN_CHECK_50: Self = Self {
        name: "KEY_SIGN_CHECK_50",
        pattern: KEY_SIGN_CHECK_50,
        offset: KEY_SIGN_CHECK_OFFSET_50,
    };

    pub const SDK_UTIL_RSA_ENCRYPT_50: Self = Self {
        name: "SDK_UTIL_RSA_ENCRYPT_50",
        pattern: SDK_UTIL_RSA_ENCRYPT_50,
        offset: 0,
    };

    // 60+ offsets
    pub const MHYRSA_PERFORM_CRYPTO_ACTION_65: Self = Self {
        name: "MHYRSA_PERFORM_CRYPTO_ACTION_65",
        pattern: MHYRSA_PERFORM_CRYPTO_ACTION_65,
        offset: 0,
    };

    pub const KEY_SIGN_CHECK_65: Self = Self {
        name: "KEY_SIGN_CHECK_65",
        pattern: KEY_SIGN_CHECK_65,
        offset: KEY_SIGN_CHECK_OFFSET_65,
    };
}


lazy_static! {
    pub static ref PUBLIC_SIGNING_DER_KEY: Vec<u8> = {
        let key = RsaPublicKey::from_public_key_pem(
            PATCHER_CONFIG.get().unwrap().encryption_config.signing_key.as_str(),
        )
        .unwrap();

        let der = key.to_pkcs1_der().unwrap();
        der.as_bytes()[2..].to_vec()
    };
    pub static ref PUBLIC_SIGNING_XML_KEY: String = {
        let key = RsaPublicKey::from_public_key_pem(
            PATCHER_CONFIG.get().unwrap().encryption_config.signing_key.as_str(),
        )
        .unwrap();

        util::rsa_public_key_to_xml(&key)
    };
    pub static ref PUBLIC_ENCRYPTION_DER_KEY: Vec<u8> = {
        let key = RsaPublicKey::from_public_key_pem(
            PATCHER_CONFIG.get().unwrap().encryption_config.encryption_key.as_str(),
        )
        .unwrap();

        let der = key.to_pkcs1_der().unwrap();
        der.as_bytes()[2..].to_vec()
    };
    pub static ref PUBLIC_ENCRYPTION_XML_KEY: String = {
        let key = RsaPublicKey::from_public_key_pem(
            PATCHER_CONFIG.get().unwrap().encryption_config.encryption_key.as_str(),
        )
        .unwrap();

        util::rsa_public_key_to_xml(&key)
    };
}

pub struct Security;
impl MhyModule for MhyContext<Security> {
    unsafe fn init(&mut self, version: GameVersion, il2cpp_api: Option<&Il2CppApi>) -> Result<()> {
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
        ModuleType::Security
    }
}

impl MhyContext<Security> {
    unsafe fn via_il2cpp(&mut self, version: GameVersion, il2cpp_api: &Il2CppApi) -> Result<()> {
        // SDK:
        let _ = self.hook_il2cpp_attach(il2cpp_api, Il2cppMethodHookInfo::SDK_UTIL_RSA_ENCRYPT, on_sdk_util_rsa_encrypt);
        let _ = self.hook_il2cpp_attach(il2cpp_api, Il2cppMethodHookInfo::MIHOYO_SDK_UTIL_RSA_ENCRYPT, on_sdk_util_rsa_encrypt);

        // extra encryption and signatures got only added in 2.8
        if version.is_before(2,7,50) {
            return Ok(());
        }

        // Dispatch/kcp:
        let rsa_util_rsa_encrypt_target = if version.is_at_least(2,7,50) && version.is_before(2,8,50){
            Il2cppMethodHookInfo::RSA_UTIL_RSA_ENCRYPT_28
        } else if version.is_at_least(2,7,50) && version.is_before(3,0,50){
            Il2cppMethodHookInfo::RSA_UTIL_RSA_ENCRYPT_30
        } else {
            Il2cppMethodHookInfo::RSA_UTIL_RSA_ENCRYPT_31
        };

        let _ = self.hook_il2cpp_attach(il2cpp_api, rsa_util_rsa_encrypt_target, on_rsa_util_rsa_encrypt);

        let rsa_util_verify_hash_target = if version.is_at_least(2,7,50) && version.is_before(2,8,50){
            Il2cppMethodHookInfo::RSA_UTIL_VERIFY_HASH_28
        } else if version.is_at_least(2,7,50) && version.is_before(3,0,50){
            Il2cppMethodHookInfo::RSA_UTIL_VERIFY_HASH_30
        } else {
            Il2cppMethodHookInfo::RSA_UTIL_VERIFY_HASH_31
        };

        let _ = self.hook_il2cpp_replace(il2cpp_api, rsa_util_verify_hash_target, verify_sucessfull);

        let rsa_util_verify_data_target = if version.is_at_least(2,7,50) && version.is_before(2,8,50){
            Il2cppMethodHookInfo::RSA_UTIL_VERIFY_DATA_28
        } else if version.is_at_least(2,7,50) && version.is_before(3,0,50){
            Il2cppMethodHookInfo::RSA_UTIL_VERIFY_DATA_30
        } else {
            Il2cppMethodHookInfo::RSA_UTIL_VERIFY_DATA_31
        };

        let _ = self.hook_il2cpp_replace(il2cpp_api, rsa_util_verify_data_target, verify_sucessfull);


        let security_get_public_rsa_key_target = if version.is_at_least(2,7,50) && version.is_before(2,8,50){
            Il2cppMethodHookInfo::SECURITY_GET_PUBLIC_KEY_28
        } else if version.is_at_least(2,7,50) && version.is_before(3,0,50){
            Il2cppMethodHookInfo::SECURITY_GET_PUBLIC_KEY_30
        } else {
            Il2cppMethodHookInfo::SECURITY_GET_PUBLIC_KEY_31
        };

        let _ = self.hook_il2cpp_replace(il2cpp_api, security_get_public_rsa_key_target, on_security_get_public_rsa_key);


        Ok(())
    }
    unsafe fn via_pattern(&mut self, version: GameVersion) -> Result<()> {
        // todo verify which versions those offsets support
        if version.is_at_least(6,4,50) {
            let _ = self.hook_pattern_attach(PatternMethodHookInfo::MHYRSA_PERFORM_CRYPTO_ACTION_65, on_mhy_rsa);
            let _ = self.hook_pattern_attach(PatternMethodHookInfo::KEY_SIGN_CHECK_65, after_key_sign_check);
            let _ = self.hook_pattern_attach(PatternMethodHookInfo::SDK_UTIL_RSA_ENCRYPT_50, on_sdk_util_rsa_encrypt);
            return Ok(())
        }
        if version.is_at_least(4, 7, 50) {
            let _ = self.hook_pattern_attach(PatternMethodHookInfo::MHYRSA_PERFORM_CRYPTO_ACTION_50, on_mhy_rsa);
            let _ = self.hook_pattern_attach(PatternMethodHookInfo::KEY_SIGN_CHECK_50, after_key_sign_check);
            let _ = self.hook_pattern_attach(PatternMethodHookInfo::SDK_UTIL_RSA_ENCRYPT_50, on_sdk_util_rsa_encrypt);
            return Ok(())
        }

        println!("not yet supported version {}", version);

        Ok(())
    }
}


unsafe extern "win64" fn after_key_sign_check(reg: *mut Registers, _: usize) {
    println!("key sign check!");
    (*reg).rax = 1
}
unsafe extern "win64" fn verify_sucessfull(
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
            PUBLIC_ENCRYPTION_DER_KEY.as_ptr(),
            (*reg).r12 as *mut u8,
            PUBLIC_ENCRYPTION_DER_KEY.len(),
        );
    }
}


unsafe fn log_current_xml_key(reg: *mut Registers, register: &REG, message: &str) {
    let log = PATCHER_CONFIG.get().unwrap().log_config.log_crypto_keys;
    if !log {
        return;
    }

    let base_address = register.read_register(reg);
    let str_length = *(base_address.wrapping_add(16) as *const u32);
    let str_ptr = base_address.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let key = String::from_utf16le(slice).unwrap();
    println!("{message} {key}");
}

unsafe extern "win64" fn on_sdk_util_rsa_encrypt(reg: *mut Registers, _: usize) {
    println!("[*] SDK RSA: replacing key");
    let target_reg = &RUNTIME_CONFIG.get().unwrap().first_arg_register;
    log_current_xml_key(reg, target_reg, "[*] SDK RSA previous key:");

    let sdk_key = &*PATCHER_CONFIG.get().unwrap().encryption_config.sdk_key;
    target_reg.set_register(reg, marshal::create_il2cpp_string(sdk_key) as u64);

    log_current_xml_key(reg, target_reg, "[*] SDK RSA new key:");
}


unsafe extern "win64" fn on_rsa_util_rsa_encrypt(reg: *mut Registers, _: usize) {
    println!("[*] RSA utils encrypt: replacing key");
    let target_reg = &RUNTIME_CONFIG.get().unwrap().first_arg_register;

    log_current_xml_key(reg, target_reg, "[*] RSA utils encrypt previous key:");

    target_reg.set_register(reg, marshal::create_il2cpp_string(&*PUBLIC_ENCRYPTION_XML_KEY) as u64);

    log_current_xml_key(reg, target_reg, "[*] RSA utils encrypt new key:");
}

unsafe extern "win64" fn on_security_get_public_rsa_key(reg: *mut Registers, _: usize, _: usize,) -> usize {
    println!("[*] MoleMoleSecurity getPublicRsaKey: replacing key");
    (*reg).rcx = marshal::create_il2cpp_string(&*PUBLIC_SIGNING_XML_KEY) as u64;

    if PATCHER_CONFIG.get().unwrap().log_config.log_crypto_keys{
        println!("[*] get rsa pub key: new key {}", &*PUBLIC_SIGNING_XML_KEY);
    }

    (*reg).rcx as usize //todo
}
