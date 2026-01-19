use crate::crypto;
use crate::crypto::{KdfParams, Key};
use crate::error::ClipassError;
use crate::vault::vault_header::{VaultHeader, HEADER_SIZE};
use crate::vault::{NONCE_SIZE, SALT_SIZE};
use aes_gcm::aead::rand_core::RngCore;
use argon2::password_hash::SaltString;
use chrono::{DateTime, Local};
use rand::thread_rng;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


pub struct Vault {
    entries: HashMap<String, String>,
    kdf_params: KdfParams,
    updated: bool,
    created_at: SystemTime,
    modified_at: SystemTime,
    salt: SaltString,
    key: Key,
}

impl Vault {
    pub fn new_empty(master_password: &str) -> Result<Self, ClipassError> {
        let mut salt_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut salt_bytes);
        let salt = SaltString::encode_b64(&salt_bytes)?;
        let (key, kdf_params) = crypto::derive_key(master_password, &salt, None)?;
        let created_at = SystemTime::now();
        Ok(Self {entries: HashMap::new(), created_at, modified_at: created_at, salt, key, kdf_params, updated: false})
    }

    pub fn new_entry(&mut self, key: &str, value: &str)
        -> Result<(), ClipassError>
    {
        if self.entries.contains_key(key) {
            return Err(ClipassError::IdExists(key.to_string()));
        }
        self.entries.insert(key.to_string(), value.to_string());
        self.updated = true;
        Ok(())
    }

    pub fn delete_entry(&mut self, key: &str)
        -> Result<(), ClipassError>
    {
        match self.entries.remove_entry(key) {
            Some(_) => { self.updated = true; Ok(()) },
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
        self.updated = true;
        Ok(())
    }

    pub fn crypt_to_file(&self, path: &str) -> Result<(), ClipassError> {
        let entries_json = serde_json::to_vec(&self.entries)?;

        let mut salt_bytes = [0u8; SALT_SIZE];
        self.salt.decode_b64(&mut salt_bytes)?;

        let nonce = crypto::generate_nonce();

        let now = SystemTime::now();
        let created_at = self.created_at.duration_since(UNIX_EPOCH)?.as_secs();
        let modified_at= match self.updated {
            true => now.duration_since(UNIX_EPOCH)?.as_secs(),
            false => self.modified_at.duration_since(UNIX_EPOCH)?.as_secs(),
        };

        let header = VaultHeader::new(self.salt.clone(), nonce, created_at, modified_at, self.kdf_params.clone());
        let header_bytes = header.serialize()?;

        let ciphertext = crypto::encrypt_data(
            &self.key,
            &nonce,
            &entries_json,
            &header_bytes
        )?;

        let mut file = File::create(path)?;
        file.write_all(&header_bytes)?;
        file.write_all(&ciphertext)?;

        Ok(())
    }

    pub fn load_from_file(master_password: &str, path: &str)
        -> Result<Self, ClipassError>
    {
        let data = fs::read(path)?;

        if data.len() < (SALT_SIZE + NONCE_SIZE) {
            return Err(ClipassError::Io("file too small or invalid".to_string()));
        }

        let header = VaultHeader::deserialize(&data)?;
        let salt = header.salt;
        let nonce = header.nonce;
        let ciphertext = &data[HEADER_SIZE..];
        let kdf_params = header.kdf;
        let created_at = UNIX_EPOCH + Duration::from_secs(header.created_at);
        let modified_at = UNIX_EPOCH + Duration::from_secs(header.modified_at);

        let (key, _) = crypto::derive_key(master_password, &salt, Some(kdf_params.clone()))?;

        let decrypted = crypto::decrypt_data(&key, &nonce, &ciphertext, &data[..HEADER_SIZE])?;
        let entries: HashMap<String, String> = serde_json::from_slice(&decrypted)?;

        Ok(Self { salt, key, entries, kdf_params, created_at, modified_at, updated: false })
    }

    pub fn created_at(&self) -> DateTime<Local>{
        DateTime::from(self.created_at)
    }

    pub fn modified_at(&self) -> DateTime<Local> {
        DateTime::from(self.modified_at)
    }
}