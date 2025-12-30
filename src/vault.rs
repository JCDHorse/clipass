use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::Nonce;
use argon2::password_hash::SaltString;
use rand::thread_rng;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Write;

use crate::crypto;
use crate::crypto::Key;
use crate::error::ClipassError;

const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

pub struct Vault {
    entries: HashMap<String, String>,
    salt: SaltString,
    key: Key,
}

impl Vault {
    pub fn new_empty(master_password: &str) -> Result<Self, ClipassError> {
        let mut salt_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes)?;
        let key = crypto::derive_key(master_password, &salt)?;
        Ok(Self {entries: HashMap::new(), salt, key})
    }

    pub fn new(entries: HashMap<String, String>, salt: SaltString, key: Key) -> Self {
        Self { entries, salt, key }
    }

    pub fn new_entry(&mut self, key: &str, value: &str)
        -> Result<(), ClipassError>
    {
        if self.entries.contains_key(key) {
            return Err(ClipassError::IdExists(key.to_string()));
        }
        self.entries.insert(key.to_string(), value.to_string());
        Ok(())
    }

    pub fn delete_entry(&mut self, key: &str)
        -> Result<(), ClipassError>
    {
        match self.entries.remove_entry(key) {
            Some(v) => Ok(()),
            None => Err(ClipassError::NotFound(key.to_string())),
        }
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn get_value(&self, key: &str) -> Result<&String, ClipassError> {
        match self.entries.get(key) {
            None => Err(ClipassError::NotFound(key.to_string())),
            Some(v) => Ok(v),
        }
    }

    pub fn get_all(&self) -> &HashMap<String, String> {
        &self.entries
    }

    pub fn update(&mut self, key: &str, value: &str) -> Result<(), ClipassError> {
        let value_ref = match self.entries.get_mut(key) {
            None => return Err(ClipassError::NotFound(key.to_string())),
            Some(v) => v,
        };
        *value_ref = value.to_string();
        Ok(())
    }

    fn crypt_write(path: &str, salt_bytes: &[u8; 32], nonce: &GenericArray<u8, U12>,
                   ciphertext: &Vec<u8>) -> Result<(), ClipassError>
    {
        let mut file = File::create(path)?;
        file.write_all(salt_bytes)?;
        file.write_all(nonce)?;
        file.write_all(ciphertext)?;
        Ok(())
    }

    pub fn crypt_to_file(&self, path: &str) -> Result<(), ClipassError> {
        let entries_json = serde_json::to_vec(&self.entries)?;

        let mut salt_bytes = [0u8; SALT_SIZE];
        self.salt.decode_b64(&mut salt_bytes)?;

        let (ciphertext, nonce) =
            crypto::encrypt_data(&self.key, &entries_json)?;

        Self::crypt_write(path, &salt_bytes, &nonce, &ciphertext)?;
        Ok(())
    }

    pub fn load_from_file(master_password: &str, path: &str)
        -> Result<Self, ClipassError>
    {
        // 1. Lecture du fichier complet
        let data = fs::read(path)?;

        // Vérification de la taille minimale (16 sel + 12 nonce)
        if data.len() < (SALT_SIZE + NONCE_SIZE) {
            return Err(ClipassError::Io("file too small or invalid".to_string()));
        }

        // Extraction des composants
        let nonce_start = SALT_SIZE;
        let nonce_end = SALT_SIZE + NONCE_SIZE;

        let salt_bytes = &data[..SALT_SIZE];
        let nonce_bytes = &data[nonce_start..nonce_end];
        let ciphertext = Vec::from(&data[nonce_end..]);

        let nonce = Nonce::from_slice(nonce_bytes);
        let salt = SaltString::encode_b64(salt_bytes)?;

        let key = crypto::derive_key(master_password, &salt)?;
        let decrypted = crypto::decrypt_data(&key, &ciphertext, nonce.as_ref())?;
        let entries: HashMap<String, String> = serde_json::from_slice(&decrypted)?;
        Ok(Self { salt, key, entries })
    }
}