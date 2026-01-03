use aes_gcm::aead::consts::{U12};
use aes_gcm::Nonce;
use argon2::password_hash::SaltString;
use crate::crypto::KdfParams;
use crate::error::ClipassError;
use crate::vault::{NONCE_SIZE, SALT_SIZE};

/**
        *** CLIPASS VAULT FILE v2 ***
*****************************************
                  HEADER
  - Magic number {4}    : "CLIP"
  - Version {2}         : 0x0002
  - Header Size {2}     : ?HEADER_SIZE
  - Created at {8}
  - Modified at {8}
  - KDF {12}            : Key Derivation parameters
    - memory_cost {4}
    - time_cost {4}
    - parallelism {4}
  - Salt {32}           : Argon2 Salt
  - Nonce {12}          : AES-GCM nonce
------------------------------------------
                  CIPHERTEXT
*****************************************/

const MAGIC: &[u8; 4] = b"CLIP";
const VERSION: u16 = 2;
const PRE_HEADER_SIZE: usize = 8; // MAGIC (4) + VERSION (2) + HEADER_SIZE (2)

const KDF_SIZE: usize = 12;

pub struct VaultHeader {
    pub created_at: u64,
    pub modified_at: u64,
    pub kdf: KdfParams,
    pub salt: SaltString,
    pub nonce: Nonce<U12>
}

impl VaultHeader {
    pub const HEADER_SIZE: usize =
        PRE_HEADER_SIZE +
        8 +  // created_at
        8 +  // modified_at
        KDF_SIZE +
        SALT_SIZE +
        NONCE_SIZE;
    pub fn new(salt: SaltString, nonce: Nonce<U12>, created_at: u64, modified_at: u64, kdf: KdfParams) -> Self {
        Self { created_at, modified_at, kdf,  nonce, salt }
    }
    pub fn serialize(&self) -> Result<Vec<u8>, ClipassError> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE);

        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&(Self::HEADER_SIZE as u16).to_le_bytes());

        // Timestamp
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.modified_at.to_le_bytes());

        // KDF
        buf.extend_from_slice(&self.kdf.memory_cost.to_le_bytes());
        buf.extend_from_slice(&self.kdf.time_cost.to_le_bytes());
        buf.extend_from_slice(&self.kdf.parallelism.to_le_bytes());

        let mut salt_bytes = [0u8; SALT_SIZE];
        self.salt.decode_b64(&mut salt_bytes)?;
        buf.extend_from_slice(salt_bytes.as_slice());

        buf.extend_from_slice(self.nonce.as_slice());

        Ok(buf)
    }

    pub fn deserialize(data: &Vec<u8>) -> Result<Self, ClipassError> {
        const CREATED_AT_START: usize = PRE_HEADER_SIZE;
        const CREATED_AT_END: usize = CREATED_AT_START + 8;
        const MODIFIED_AT_START: usize = CREATED_AT_END;
        const MODIFIED_AT_END: usize = MODIFIED_AT_START + 8;
        const KDF_START: usize = PRE_HEADER_SIZE + 16;
        const KDF_END: usize = KDF_START + KDF_SIZE;
        const SALT_START: usize = KDF_END;
        const SALT_END: usize = SALT_START + SALT_SIZE;
        const NONCE_START: usize = SALT_END;
        const NONCE_END: usize = NONCE_START + NONCE_SIZE;

        let magic: &[u8] = &data[0..4];
        if magic != MAGIC {
            return Err(ClipassError::HeaderError("bad magic".to_string()));
        }

        // TODO : Remove all these .unwrap()

        let version = u16::from_le_bytes(data[4..6].try_into().unwrap());
        if version != VERSION {
            return Err(ClipassError::HeaderError("incompatible version".to_string()))
        }

        let created_at = u64::from_le_bytes(data[CREATED_AT_START..CREATED_AT_END].try_into().unwrap());
        let modified_at = u64::from_le_bytes(data[MODIFIED_AT_START..MODIFIED_AT_END].try_into().unwrap());

        let kdf_bytes = &data[KDF_START .. KDF_END];
        let memory_cost: u32 = u32::from_le_bytes(kdf_bytes[0..4].try_into().unwrap());
        let time_cost: u32 = u32::from_le_bytes(kdf_bytes[4..8].try_into().unwrap());
        let parallelism: u32 = u32::from_le_bytes(kdf_bytes[8..12].try_into().unwrap());
        let kdf = KdfParams { memory_cost, time_cost, parallelism };

        let salt = SaltString::encode_b64(&data[SALT_START..SALT_END])?;
        let nonce = Nonce::from_slice(&data[NONCE_START..NONCE_END]).clone();

        Ok(Self { kdf, created_at, modified_at, salt, nonce })
    }
}
