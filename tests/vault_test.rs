use tempfile::NamedTempFile;
use clipass::error::ClipassError;
use clipass::vault::Vault;

#[test]
fn vault_encrypt_decrypt_roundtrip() -> Result<(), ClipassError> {
    let mut vault = Vault::new_empty("test-pass")?;
    vault.new_entry("email", "poney@gmail.com")?;
    let tmp = NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    vault.crypt_to_file(path)?;

    let loaded = Vault::load_from_file("test-pass", path)?;
    let value = loaded.get_value("email")?;
    assert_eq!(value, "poney@gmail.com");
    Ok(())
}
#[test]
fn vault_wrong_password_fails() -> Result<(), ClipassError> {
    let mut vault = Vault::new_empty("correct-password")?;
    vault.new_entry("key", "secret")?;

    let tmp = NamedTempFile::new()?;
    let path = tmp.path().to_str().unwrap();
    vault.crypt_to_file(path)?;

    // Attempt to load with wrong password — expect an Err (CryptoError)
    let res = Vault::load_from_file("wrong-password", path);
    assert!(res.is_err());
    // optionally inspect variant
    match res {
        Err(e) => match e {
            ClipassError::CryptoError(_) => {}
            _ => panic!("expected CryptoError on wrong password, got {:?}", e),
        },
        Ok(_) => panic!("expected error for wrong password"),
    }
    Ok(())
}

#[test]
fn new_entry_duplicate_returns_error() -> Result<(), ClipassError> {
    let mut vault = Vault::new_empty("test-pass")?;
    vault.new_entry("dup", "one").expect("first insert ok");
    let second = vault.new_entry("dup", "two");
    assert!(second.is_err());
    match second {
        Err(clipass::error::ClipassError::IdExists(id)) => {
            assert_eq!(id, "dup");
            Ok(())
        },
        Err(e) => panic!("expected IdExists, got {:?}", e),
        Ok(_) => panic!("expected error"),
    }
}