use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Write;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::aead::rand_core::RngCore;
use argon2::Argon2;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use crate::error::ClipassError;

const SALT_SIZE: usize = 16;

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    entries: HashMap<String, String>,
    salt: [u8; SALT_SIZE],
}

impl Vault {
    pub fn new(_salt: Option<[u8; 16]>) -> Self {
        let mut salt: [u8; SALT_SIZE];
        if _salt.is_none() {
            salt = [0u8; SALT_SIZE];
            thread_rng().fill_bytes(&mut salt);
        }
        else {
            salt = _salt.unwrap();
        }
        Self { entries: HashMap::new(), salt }
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

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn get_value(&self, key: &str) -> Result<&String, ClipassError> {
        match self.entries.get(key) {
            None => Err(ClipassError::NotFound),
            Some(v) => Ok(v),
        }
    }

    pub fn get_all(&self) -> &HashMap<String, String> {
        &self.entries
    }
    pub fn save_to_file(&self, master_password: &str, path: &str)
        -> Result<(), Box<dyn std::error::Error>>
    {
        let mut file = File::create(path)?;
        let serialized = serde_json::to_string(self)?;
        file.write(serialized.as_bytes())?;
        Ok(())
    }

    pub fn crypt_to_file(&self, master_password: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Préparation des données
        let json_data = serde_json::to_vec(self)?;

        // 2. Dérivation de la clé (KDF)
        let salt = self.salt;
        let mut key_bytes = [0u8; 32];
        Argon2::default().hash_password_into(master_password.as_bytes(), &salt, &mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // 3. Chiffrement
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, json_data.as_ref())
            .map_err(|e| format!("Erreur de chiffrement : {}", e))?;

        // 4. Stockage (On concatène Nonce + Ciphertext pour pouvoir déchiffrer plus tard)
        // Fichier = [SALT (16)] + [NONCE (12)] + [DONNÉES CHIFFRÉES]
        let mut final_data = Vec::with_capacity(SALT_SIZE + 12 + ciphertext.len());
        final_data.extend_from_slice(&self.salt);     // On ajoute le sel en clair
        final_data.extend_from_slice(&nonce_bytes);   // On ajoute le nonce en clair
        final_data.extend_from_slice(&ciphertext);    // On ajoute le secret

        let mut file = File::create(path)?;
        file.write_all(&final_data)?;

        Ok(())

    }
    pub fn load_from_file(master_password: &str, path: &str)
                          -> Result<Self, Box<dyn std::error::Error>>
    {
        // 1. Lecture du fichier complet
        let data = fs::read(path)?;

        // Vérification de la taille minimale (16 sel + 12 nonce)
        if data.len() < (SALT_SIZE + 12) {
            return Err("Fichier trop court ou invalide".into());
        }

        // Extraction des composants
        let salt_bytes = &data[0..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];

        // 2. Régénération de la clé (doit être identique à save_to_file)
        let mut key_bytes = [0u8; 32];
        Argon2::default().hash_password_into(
            master_password.as_bytes(),
            salt_bytes,
            &mut key_bytes
        );
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        // 3. Déchiffrement
        let decrypted_data = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Mot de passe incorrect ou données corrompues")?;

        // 4. Désérialisation
        let vault: Vault = serde_json::from_slice(&decrypted_data)?;
        if cfg!(debug_assertions) {
            println!("nonce: {:?}", nonce_bytes);
            println!("salt: {:?}", vault.salt);
            println!("key: {:?}", key);
        }
        Ok(vault)
    }
}