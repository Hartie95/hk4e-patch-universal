use std::{
    ffi::{c_char, c_void, CString},
    mem::transmute_copy,
};

use windows::{
    core::{PCSTR},
    Win32::{
        Foundation::HMODULE,
        System::LibraryLoader::{GetProcAddress},
    },
};

#[repr(C)]
pub struct Il2CppDomain {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Il2CppAssembly {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Il2CppImage {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Il2CppClass {
    _private: [u8; 0],
}

#[repr(C)]
pub struct MethodInfo {
    _private: [u8; 0],
}

type Il2CppDomainGet =
unsafe extern "C" fn() -> *mut Il2CppDomain;

type Il2CppDomainAssemblyOpen =
unsafe extern "C" fn(
    domain: *mut Il2CppDomain,
    name: *const c_char,
) -> *const Il2CppAssembly;

type Il2CppAssemblyGetImage =
unsafe extern "C" fn(
    assembly: *const Il2CppAssembly,
) -> *const Il2CppImage;

type Il2CppClassFromName =
unsafe extern "C" fn(
    image: *const Il2CppImage,
    namespace: *const c_char,
    name: *const c_char,
) -> *mut Il2CppClass;

type Il2CppClassGetMethodFromName =
unsafe extern "C" fn(
    class: *mut Il2CppClass,
    name: *const c_char,
    argument_count: i32,
) -> *const MethodInfo;

unsafe fn get_export<T>(
    module: HMODULE,
    name: &'static [u8],
) -> Option<T>
where
    T: Copy,
{
    let address = GetProcAddress(module, PCSTR(name.as_ptr()))?;

    Some(transmute_copy(&address))
}
pub struct Il2CppApi {
    domain_get: Il2CppDomainGet,
    domain_assembly_open: Il2CppDomainAssemblyOpen,
    assembly_get_image: Il2CppAssemblyGetImage,
    class_from_name: Il2CppClassFromName,
    class_get_method_from_name: Il2CppClassGetMethodFromName,
}

impl Il2CppApi {
    pub unsafe fn load(module: HMODULE) -> Option<Self> {
        Some(Self {
            domain_get: get_export(
                module,
                b"il2cpp_domain_get\0",
            )?,
            domain_assembly_open: get_export(
                module,
                b"il2cpp_domain_assembly_open\0",
            )?,
            assembly_get_image: get_export(
                module,
                b"il2cpp_assembly_get_image\0",
            )?,
            class_from_name: get_export(
                module,
                b"il2cpp_class_from_name\0",
            )?,
            class_get_method_from_name: get_export(
                module,
                b"il2cpp_class_get_method_from_name\0",
            )?,
        })
    }
}

unsafe fn find_method(
    api: &Il2CppApi,
    assembly_name: &str,
    namespace: &str,
    class_name: &str,
    method_name: &str,
    argument_count: i32,
) -> Option<*const MethodInfo> {
    let assembly_name = CString::new(assembly_name).ok()?;
    let namespace = CString::new(namespace).ok()?;
    let class_name = CString::new(class_name).ok()?;
    let method_name = CString::new(method_name).ok()?;

    let domain = (api.domain_get)();
    if domain.is_null() {
        return None;
    }

    let assembly = (api.domain_assembly_open)(
        domain,
        assembly_name.as_ptr(),
    );

    if assembly.is_null() {
        return None;
    }

    let image = (api.assembly_get_image)(assembly);
    if image.is_null() {
        return None;
    }

    let class = (api.class_from_name)(
        image,
        namespace.as_ptr(),
        class_name.as_ptr(),
    );

    if class.is_null() {
        return None;
    }

    let method = (api.class_get_method_from_name)(
        class,
        method_name.as_ptr(),
        argument_count,
    );

    (!method.is_null()).then_some(method)
}

unsafe fn method_pointer_legacy(
    method: *const MethodInfo,
) -> Option<*mut c_void> {
    if method.is_null() {
        return None;
    }

    let address = *(method.cast::<*mut c_void>());
    (!address.is_null()).then_some(address)
}

pub unsafe fn find_method_pointer(
    api: &Il2CppApi,
    assembly_name: &str,
    namespace: &str,
    class_name: &str,
    method_name: &str,
    argument_count: i32,) -> Option<*mut c_void> {
    let method = find_method(
        &api,
        assembly_name,
        namespace,
        class_name,
        method_name,
        argument_count,
    );

    match method {
        Some(method) => {
            method_pointer_legacy(method)
        }
        None => {
            None
        }
    }
}

