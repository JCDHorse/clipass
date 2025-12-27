use aes_gcm::aead::generic_array::{typenum, GenericArray};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::aead::consts::U12;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::rand_core::RngCore;
use argon2::password_hash::SaltString;
use rand::thread_rng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::ClipassError;

#[derive(Clone, ZeroizeOnDrop)]
pub struct Key(GenericArray<u8, typenum::U32>);

impl Key {
    fn new(data: GenericArray<u8, typenum::U32>) -> Self {
        Self(data)
    }
}

pub fn derive_key(password: &str, salt: &SaltString) -> Result<Key, ClipassError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, None)?
    );

    let hash = argon2.hash_password(password.as_bytes(), salt)?;
    let hash_output = hash.hash.ok_or(ClipassError::CryptoError("hash error".to_string()))?;
    let key_bytes = hash_output.as_bytes();

    let mut key_array = [0u8; 32];
    let len = std::cmp::min(key_bytes.len(), 32);
    key_array[..len].copy_from_slice(&key_bytes[..len]);

    let key = Key::new(*GenericArray::from_slice(&key_array));

    key_array.zeroize();
    Ok(key)
}

pub fn encrypt_data(key: &Key, plaintext: &Vec<u8>)
    -> Result<(Vec<u8>, GenericArray<u8, U12>), ClipassError>
{
    let cipher = Aes256Gcm::new(&key.0);
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;
    Ok((ciphertext, nonce))
}

pub fn decrypt_data(key: &Key, ciphertext: &Vec<u8>, nonce: &[u8; 12])
    -> Result<Vec<u8>, ClipassError>
{
    let cipher = Aes256Gcm::new(&key.0);
    let nonce = GenericArray::from_slice(nonce);
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(v) => Ok(v),
        Err(err) => Err(ClipassError::CryptoError(format!("{err}"))),
    }
}