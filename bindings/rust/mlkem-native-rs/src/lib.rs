use rand_core::TryCryptoRng;
use std::default::Default;
use thiserror::Error;

mod unsafe_bindings_level2;
mod unsafe_bindings_level3;
mod unsafe_bindings_level4;

/// .
///
/// # Panics
///
/// Panics always.
///
/// # Safety
///
/// .
#[no_mangle]
pub unsafe extern "C" fn randombytes(
    _buf: *mut u8,
    _len: core::ffi::c_longlong,
) -> core::ffi::c_int {
    panic!("");
}

#[derive(Error, Debug)]
pub enum MLKEMNativeError {
    #[error("the CSRNG failed due to insufficent entropy")]
    InsufficentEntropy,
    #[error("the library function encountered an internal error")]
    LibraryError,
}

macro_rules! reexport_const {
    ( $type_name:ident, $struct_name:ident ) => {
        pub const $type_name: usize = unsafe_bindings_level2::$type_name as usize;

        #[derive(Debug, PartialEq)]
        pub struct $struct_name([u8; $type_name]);

        impl Default for $struct_name {
            fn default() -> Self {
                Self([0u8; $type_name])
            }
        }
    };
}

reexport_const!(MLKEM512_SECRETKEYBYTES, MLKEM512SecretKey);
reexport_const!(MLKEM512_PUBLICKEYBYTES, MLKEM512PublicKey);
reexport_const!(MLKEM512_CIPHERTEXTBYTES, MLKEM512Ciphertext);
reexport_const!(MLKEM512_BYTES, MLKEM512SharedSecret);

reexport_const!(MLKEM768_SECRETKEYBYTES, MLKEM768SecretKey);
reexport_const!(MLKEM768_PUBLICKEYBYTES, MLKEM768PublicKey);
reexport_const!(MLKEM768_CIPHERTEXTBYTES, MLKEM768Ciphertext);
reexport_const!(MLKEM768_BYTES, MLKEM768SharedSecret);

reexport_const!(MLKEM1024_SECRETKEYBYTES, MLKEM1024SecretKey);
reexport_const!(MLKEM1024_PUBLICKEYBYTES, MLKEM1024PublicKey);
reexport_const!(MLKEM1024_CIPHERTEXTBYTES, MLKEM1024Ciphertext);
reexport_const!(MLKEM1024_BYTES, MLKEM1024SharedSecret);

pub fn mlkem512_keypair(
    rng: &mut impl TryCryptoRng,
) -> Result<(MLKEM512SecretKey, MLKEM512PublicKey), MLKEMNativeError> {
    let mut sk = MLKEM512SecretKey::default();
    let mut pk = MLKEM512PublicKey::default();

    let mut coins = [0u8; 2 * (unsafe_bindings_level2::MLKEM512_SYMBYTES as usize)];
    rng.try_fill_bytes(&mut coins)
        .map_err(|_| MLKEMNativeError::InsufficentEntropy)?;

    let success = unsafe {
        unsafe_bindings_level2::PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(
            pk.0.as_mut_ptr(),
            sk.0.as_mut_ptr(),
            coins.as_ptr(),
        )
    };

    if success == 0 {
        Ok((sk, pk))
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem512_enc(
    rng: &mut impl TryCryptoRng,
    pk: &MLKEM768PublicKey,
) -> Result<(MLKEM768Ciphertext, MLKEM768SharedSecret), MLKEMNativeError> {
    let mut ct = MLKEM768Ciphertext::default();
    let mut ss = MLKEM768SharedSecret::default();

    let mut coins = [0u8; unsafe_bindings_level2::MLKEM768_SYMBYTES as usize];
    rng.try_fill_bytes(&mut coins)
        .map_err(|_| MLKEMNativeError::InsufficentEntropy)?;

    let success = unsafe {
        unsafe_bindings_level2::PQCP_MLKEM_NATIVE_MLKEM512_enc_derand(
            ct.0.as_mut_ptr(),
            ss.0.as_mut_ptr(),
            pk.0.as_ptr(),
            coins.as_ptr(),
        )
    };

    if success == 0 {
        Ok((ct, ss))
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem512_dec(
    sk: &MLKEM768SecretKey,
    ct: &MLKEM768Ciphertext,
) -> Result<MLKEM768SharedSecret, MLKEMNativeError> {
    let mut ss = MLKEM768SharedSecret::default();

    let success = unsafe {
        unsafe_bindings_level2::PQCP_MLKEM_NATIVE_MLKEM512_dec(
            ss.0.as_mut_ptr(),
            ct.0.as_ptr(),
            sk.0.as_ptr(),
        )
    };

    if success == 0 {
        Ok(ss)
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem768_keypair(
    rng: &mut impl TryCryptoRng,
) -> Result<(MLKEM768SecretKey, MLKEM768PublicKey), MLKEMNativeError> {
    let mut sk = MLKEM768SecretKey::default();
    let mut pk = MLKEM768PublicKey::default();

    let mut coins = [0u8; 2 * (unsafe_bindings_level2::MLKEM768_SYMBYTES as usize)];
    rng.try_fill_bytes(&mut coins)
        .map_err(|_| MLKEMNativeError::InsufficentEntropy)?;

    let success = unsafe {
        unsafe_bindings_level3::PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(
            pk.0.as_mut_ptr(),
            sk.0.as_mut_ptr(),
            coins.as_ptr(),
        )
    };

    if success == 0 {
        Ok((sk, pk))
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem768_enc(
    rng: &mut impl TryCryptoRng,
    pk: &MLKEM768PublicKey,
) -> Result<(MLKEM768Ciphertext, MLKEM768SharedSecret), MLKEMNativeError> {
    let mut ct = MLKEM768Ciphertext::default();
    let mut ss = MLKEM768SharedSecret::default();

    let mut coins = [0u8; unsafe_bindings_level2::MLKEM768_SYMBYTES as usize];
    rng.try_fill_bytes(&mut coins)
        .map_err(|_| MLKEMNativeError::InsufficentEntropy)?;

    let success = unsafe {
        unsafe_bindings_level3::PQCP_MLKEM_NATIVE_MLKEM768_enc_derand(
            ct.0.as_mut_ptr(),
            ss.0.as_mut_ptr(),
            pk.0.as_ptr(),
            coins.as_ptr(),
        )
    };

    if success == 0 {
        Ok((ct, ss))
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem768_dec(
    sk: &MLKEM768SecretKey,
    ct: &MLKEM768Ciphertext,
) -> Result<MLKEM768SharedSecret, MLKEMNativeError> {
    let mut ss = MLKEM768SharedSecret::default();

    let success = unsafe {
        unsafe_bindings_level3::PQCP_MLKEM_NATIVE_MLKEM768_dec(
            ss.0.as_mut_ptr(),
            ct.0.as_ptr(),
            sk.0.as_ptr(),
        )
    };

    if success == 0 {
        Ok(ss)
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem1024_keypair(
    rng: &mut impl TryCryptoRng,
) -> Result<(MLKEM768SecretKey, MLKEM768PublicKey), MLKEMNativeError> {
    let mut sk = MLKEM768SecretKey::default();
    let mut pk = MLKEM768PublicKey::default();

    let mut coins = [0u8; 2 * (unsafe_bindings_level2::MLKEM1024_SYMBYTES as usize)];
    rng.try_fill_bytes(&mut coins)
        .map_err(|_| MLKEMNativeError::InsufficentEntropy)?;

    let success = unsafe {
        unsafe_bindings_level4::PQCP_MLKEM_NATIVE_MLKEM1024_keypair_derand(
            pk.0.as_mut_ptr(),
            sk.0.as_mut_ptr(),
            coins.as_ptr(),
        )
    };

    if success == 0 {
        Ok((sk, pk))
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem1024_enc(
    rng: &mut impl TryCryptoRng,
    pk: &MLKEM768PublicKey,
) -> Result<(MLKEM768Ciphertext, MLKEM768SharedSecret), MLKEMNativeError> {
    let mut ct = MLKEM768Ciphertext::default();
    let mut ss = MLKEM768SharedSecret::default();

    let mut coins = [0u8; unsafe_bindings_level2::MLKEM1024_SYMBYTES as usize];
    rng.try_fill_bytes(&mut coins)
        .map_err(|_| MLKEMNativeError::InsufficentEntropy)?;

    let success = unsafe {
        unsafe_bindings_level4::PQCP_MLKEM_NATIVE_MLKEM1024_enc_derand(
            ct.0.as_mut_ptr(),
            ss.0.as_mut_ptr(),
            pk.0.as_ptr(),
            coins.as_ptr(),
        )
    };

    if success == 0 {
        Ok((ct, ss))
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}

pub fn mlkem1024_dec(
    sk: &MLKEM768SecretKey,
    ct: &MLKEM768Ciphertext,
) -> Result<MLKEM768SharedSecret, MLKEMNativeError> {
    let mut ss = MLKEM768SharedSecret::default();

    let success = unsafe {
        unsafe_bindings_level4::PQCP_MLKEM_NATIVE_MLKEM1024_dec(
            ss.0.as_mut_ptr(),
            ct.0.as_ptr(),
            sk.0.as_ptr(),
        )
    };

    if success == 0 {
        Ok(ss)
    } else {
        Err(MLKEMNativeError::LibraryError)
    }
}
