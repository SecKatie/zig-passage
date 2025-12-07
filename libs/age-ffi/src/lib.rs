//! FFI wrapper for the age encryption library.
//!
//! Provides C-compatible functions for encrypt, decrypt, and key generation
//! that can be called from Zig.

use age::secrecy::ExposeSecret;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::raw::c_char;
use std::str::FromStr;

/// Result codes for FFI functions
#[repr(C)]
pub enum AgeResult {
    Success = 0,
    InvalidInput = 1,
    EncryptionFailed = 2,
    DecryptionFailed = 3,
    KeygenFailed = 4,
    IoError = 5,
    InvalidRecipient = 6,
    InvalidIdentity = 7,
}

/// A keypair containing public and private keys as C strings.
/// Caller must free both strings using age_free_string.
#[repr(C)]
pub struct AgeKeypair {
    pub public_key: *mut c_char,
    pub private_key: *mut c_char,
}

/// Decrypt data from a file using an identity file.
///
/// # Arguments
/// * `encrypted_path` - Path to the encrypted .age file
/// * `identity_path` - Path to the identity file containing the secret key
/// * `output` - Pointer to receive the decrypted data (caller must free with age_free_string)
/// * `output_len` - Pointer to receive the length of the decrypted data
///
/// # Returns
/// AgeResult indicating success or failure
#[no_mangle]
pub extern "C" fn age_decrypt_file(
    encrypted_path: *const c_char,
    identity_path: *const c_char,
    output: *mut *mut c_char,
    output_len: *mut usize,
) -> AgeResult {
    // Safety: validate inputs
    if encrypted_path.is_null() || identity_path.is_null() || output.is_null() || output_len.is_null() {
        return AgeResult::InvalidInput;
    }

    let encrypted_path = unsafe {
        match CStr::from_ptr(encrypted_path).to_str() {
            Ok(s) => s,
            Err(_) => return AgeResult::InvalidInput,
        }
    };

    let identity_path = unsafe {
        match CStr::from_ptr(identity_path).to_str() {
            Ok(s) => s,
            Err(_) => return AgeResult::InvalidInput,
        }
    };

    // Read identity file
    let identity_contents = match std::fs::read_to_string(identity_path) {
        Ok(s) => s,
        Err(_) => return AgeResult::IoError,
    };

    // Parse identities
    let identities: Vec<Box<dyn age::Identity>> = identity_contents
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| {
            age::x25519::Identity::from_str(line)
                .ok()
                .map(|i| Box::new(i) as Box<dyn age::Identity>)
        })
        .collect();

    if identities.is_empty() {
        return AgeResult::InvalidIdentity;
    }

    // Open encrypted file
    let encrypted_file = match File::open(encrypted_path) {
        Ok(f) => f,
        Err(_) => return AgeResult::IoError,
    };

    // Create decryptor
    let decryptor = match age::Decryptor::new(encrypted_file) {
        Ok(d) => d,
        Err(_) => return AgeResult::DecryptionFailed,
    };

    // Decrypt
    let mut decrypted = Vec::new();
    let mut reader = match decryptor.decrypt(identities.iter().map(|i| i.as_ref())) {
        Ok(r) => r,
        Err(_) => return AgeResult::DecryptionFailed,
    };
    if reader.read_to_end(&mut decrypted).is_err() {
        return AgeResult::DecryptionFailed;
    }

    // Convert to C string (note: this adds a null terminator)
    // We also need to handle binary data, so use raw pointer
    let c_output = match CString::new(decrypted.clone()) {
        Ok(s) => s,
        Err(_) => {
            // Data contains null bytes, allocate raw
            let ptr = unsafe {
                let ptr = libc::malloc(decrypted.len() + 1) as *mut c_char;
                if ptr.is_null() {
                    return AgeResult::IoError;
                }
                std::ptr::copy_nonoverlapping(decrypted.as_ptr(), ptr as *mut u8, decrypted.len());
                *ptr.add(decrypted.len()) = 0;
                ptr
            };
            unsafe {
                *output = ptr;
                *output_len = decrypted.len();
            }
            return AgeResult::Success;
        }
    };

    unsafe {
        *output_len = decrypted.len();
        *output = c_output.into_raw();
    }

    AgeResult::Success
}

/// Encrypt data to a file using a recipient.
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `plaintext_len` - Length of the plaintext
/// * `output_path` - Path to write the encrypted .age file
/// * `recipient` - The recipient public key (age1...) or path to recipients file
///
/// # Returns
/// AgeResult indicating success or failure
#[no_mangle]
pub extern "C" fn age_encrypt_to_file(
    plaintext: *const c_char,
    plaintext_len: usize,
    output_path: *const c_char,
    recipient: *const c_char,
) -> AgeResult {
    if plaintext.is_null() || output_path.is_null() || recipient.is_null() {
        return AgeResult::InvalidInput;
    }

    let plaintext = unsafe { std::slice::from_raw_parts(plaintext as *const u8, plaintext_len) };

    let output_path = unsafe {
        match CStr::from_ptr(output_path).to_str() {
            Ok(s) => s,
            Err(_) => return AgeResult::InvalidInput,
        }
    };

    let recipient_str = unsafe {
        match CStr::from_ptr(recipient).to_str() {
            Ok(s) => s,
            Err(_) => return AgeResult::InvalidInput,
        }
    };

    // Parse recipients - could be a file path or a direct recipient key
    let recipients: Vec<Box<dyn age::Recipient + Send>> = if recipient_str.starts_with("age1") {
        // Direct recipient key
        match recipient_str.parse::<age::x25519::Recipient>() {
            Ok(r) => vec![Box::new(r)],
            Err(_) => return AgeResult::InvalidRecipient,
        }
    } else {
        // Treat as file path
        let contents = match std::fs::read_to_string(recipient_str) {
            Ok(s) => s,
            Err(_) => return AgeResult::IoError,
        };

        contents
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .filter_map(|line| {
                line.trim()
                    .parse::<age::x25519::Recipient>()
                    .ok()
                    .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
            })
            .collect()
    };

    if recipients.is_empty() {
        return AgeResult::InvalidRecipient;
    }

    // Create output file
    let output_file = match File::create(output_path) {
        Ok(f) => f,
        Err(_) => return AgeResult::IoError,
    };

    // Create encryptor
    let encryptor = match age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient)) {
        Ok(e) => e,
        Err(_) => return AgeResult::EncryptionFailed,
    };

    // Encrypt
    let mut writer = match encryptor.wrap_output(output_file) {
        Ok(w) => w,
        Err(_) => return AgeResult::EncryptionFailed,
    };

    if writer.write_all(plaintext).is_err() {
        return AgeResult::EncryptionFailed;
    }

    if writer.finish().is_err() {
        return AgeResult::EncryptionFailed;
    }

    AgeResult::Success
}

/// Generate a new age keypair.
///
/// # Arguments
/// * `keypair` - Pointer to receive the generated keypair
///
/// # Returns
/// AgeResult indicating success or failure
#[no_mangle]
pub extern "C" fn age_generate_keypair(keypair: *mut AgeKeypair) -> AgeResult {
    if keypair.is_null() {
        return AgeResult::InvalidInput;
    }

    // Generate new identity
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let private_key = identity.to_string().expose_secret().to_string();

    // Convert to C strings
    let c_public = match CString::new(public_key) {
        Ok(s) => s,
        Err(_) => return AgeResult::KeygenFailed,
    };

    let c_private = match CString::new(private_key) {
        Ok(s) => s,
        Err(_) => return AgeResult::KeygenFailed,
    };

    unsafe {
        (*keypair).public_key = c_public.into_raw();
        (*keypair).private_key = c_private.into_raw();
    }

    AgeResult::Success
}

/// Free a string allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by one of the age_* functions.
#[no_mangle]
pub extern "C" fn age_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

/// Free a keypair allocated by age_generate_keypair.
///
/// # Safety
/// The keypair must have been allocated by age_generate_keypair.
#[no_mangle]
pub extern "C" fn age_free_keypair(keypair: *mut AgeKeypair) {
    if !keypair.is_null() {
        unsafe {
            if !(*keypair).public_key.is_null() {
                drop(CString::from_raw((*keypair).public_key));
            }
            if !(*keypair).private_key.is_null() {
                drop(CString::from_raw((*keypair).private_key));
            }
        }
    }
}

// Need libc for malloc in the binary data case
extern crate libc;
