use std::fmt;
use std::fmt::{format, Formatter};
use std::io::{Error, ErrorKind};
use std::convert::Infallible;
use std::num::ParseIntError;

#[derive(Debug)]
pub enum ClipassError {
    NotFound(String),
    InvalidCommand(String),
    Io(String),
    IdExists(String),
    Input(String),
    GenericError(String),
    Argon2Error(String),
    CryptoError(String),
    SerdeError(String),
}

impl fmt::Display for ClipassError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ClipassError::NotFound(s) => write!(f, "unfindable entry {s}"),
            ClipassError::InvalidCommand(cmd) => write!(f, "invalid command: {cmd}"),
            ClipassError::Io(err) => write!(f, "io error: {err}"),
            ClipassError::IdExists(id) => write!(f, "id exists already: {id}"),
            ClipassError::Input(input) => write!(f, "input error: {input}"),
            ClipassError::GenericError(err) => write!(f, "unknown error: {err}"),
            ClipassError::Argon2Error(err) => write!(f, "argon2 error: {err}"),
            ClipassError::CryptoError(err) => write!(f, "crypto error: {err}"),
            ClipassError::SerdeError(err) => write!(f, "serde error: {err}"),
        }
    }
}

impl std::error::Error for ClipassError {}

impl From<std::io::Error> for ClipassError {
    fn from(value: Error) -> Self {
        ClipassError::Io(format!("{value}"))
    }
}

impl From<Infallible> for ClipassError {
    fn from(_: Infallible) -> Self {
        // Comme c'est "Infallible", ce code ne sera techniquement jamais exécuté,
        // mais il est nécessaire pour satisfaire le compilateur.
        unreachable!()
    }
}

impl From<ParseIntError> for ClipassError {
    fn from(value: ParseIntError) -> Self {
        ClipassError::Input(value.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for ClipassError {
    fn from(value: Box<dyn std::error::Error>) -> Self {
        ClipassError::GenericError(format!("{value}"))
    }
}
impl From<serde_json::Error> for ClipassError {
    fn from(value: serde_json::Error) -> Self {
        ClipassError::SerdeError(format!("{value}"))
    }
}

impl From<argon2::Error> for ClipassError {
    fn from(value: argon2::Error) -> Self {
        ClipassError::Argon2Error(format!("{value}"))
    }
}

impl From<aes_gcm::Error> for ClipassError {
    fn from(value: aes_gcm::Error) -> Self {
        ClipassError::CryptoError(format!("{}", value))
    }
}

impl From<argon2::password_hash::Error> for ClipassError {
    fn from(value: argon2::password_hash::Error) -> Self {
        ClipassError::CryptoError(format!("{value}"))
    }
}