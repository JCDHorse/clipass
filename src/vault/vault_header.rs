use std::io::{Cursor, Read};
use aes_gcm::aead::consts::U12;
use aes_gcm::Nonce;
use argon2::password_hash::SaltString;
use crate::crypto::{KdfParams, KDF_SIZE};
use crate::error::ClipassError;
use crate::vault::{NONCE_SIZE, SALT_SIZE};

/*
        *** CLIPASS VAULT FILE v3 ***
*****************************************
                  HEADER
  - Magic number {4}    : "CLIP"
  - Version {2}         : 0x0003
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
****************************************
*/

const MAGIC_SIZE: usize = 4;
const MAGIC: [u8; MAGIC_SIZE] = *b"CLIP";
const VERSION: u16 = 3;
const PRE_HEADER_SIZE: usize = 8; // MAGIC (4) + VERSION (2) + HEADER_SIZE (2)
const TIMESTAMP_SIZE: usize = 8;
pub const HEADER_SIZE: usize =
    PRE_HEADER_SIZE +
        TIMESTAMP_SIZE * 2 + // created_at + modified_at
        KDF_SIZE +
        SALT_SIZE +
        NONCE_SIZE;

pub struct VaultHeader {
    pub created_at: u64,
    pub modified_at: u64,
    pub kdf: KdfParams,
    pub salt: SaltString,
    pub nonce: Nonce<U12>
}

impl VaultHeader {
    pub fn new(salt: SaltString, nonce: Nonce<U12>, created_at: u64, modified_at: u64, kdf: KdfParams) -> Self {
        Self { created_at, modified_at, kdf,  nonce, salt }
    }
    pub fn serialize(&self) -> Result<Vec<u8>, ClipassError> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);

        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());

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
        let mut cursor = Cursor::new(data);

        // --- helpers locaux ---
        fn read_exact<const N: usize>(cursor: &mut Cursor<&Vec<u8>>) -> Result<[u8; N], ClipassError> {
            let mut buf = [0u8; N];
            cursor.read_exact(&mut buf)?;
            Ok(buf)
        }

        // --- magic ---
        let magic = read_exact::<4>(&mut cursor)?;
        if magic != MAGIC {
            return Err(ClipassError::HeaderError("bad magic".to_string()));
        }

        // --- version ---
        let version = u16::from_le_bytes(read_exact::<2>(&mut cursor)?);
        if version != VERSION {
            return Err(ClipassError::HeaderError("incompatible version".to_string()));
        }

        let _header_size = u16::from_le_bytes(read_exact::<2>(&mut cursor)?);

        // --- created / modified ---
        let created_at = u64::from_le_bytes(read_exact::<8>(&mut cursor)?);
        let modified_at = u64::from_le_bytes(read_exact::<8>(&mut cursor)?);

        // --- KDF ---
        let memory_cost = u32::from_le_bytes(read_exact::<4>(&mut cursor)?);
        let time_cost = u32::from_le_bytes(read_exact::<4>(&mut cursor)?);
        let parallelism = u32::from_le_bytes(read_exact::<4>(&mut cursor)?);

        let kdf = KdfParams {
            memory_cost,
            time_cost,
            parallelism,
        };

        // --- salt ---
        let salt_bytes = read_exact::<SALT_SIZE>(&mut cursor)?;
        let salt = SaltString::encode_b64(&salt_bytes)?;

        // --- nonce ---
        let nonce_bytes = read_exact::<NONCE_SIZE>(&mut cursor)?;
        let nonce = Nonce::from_slice(&nonce_bytes).clone();

        Ok(Self {
            kdf,
            created_at,
            modified_at,
            salt,
            nonce,
        })
    }
}
