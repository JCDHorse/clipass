use std::fmt;
use std::fmt::{write, Formatter};
use std::io::{Error, ErrorKind};
use std::convert::Infallible;
use std::num::ParseIntError;

#[derive(Debug)]
pub enum ClipassError {
    NotFound,
    InvalidCommand(String),
    Io(std::io::Error),
    IdExists(String),
    Input(String),
}

impl fmt::Display for ClipassError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ClipassError::NotFound => write!(f, "unfindable entry"),
            ClipassError::InvalidCommand(cmd) => write!(f, "invalid command: {}", cmd),
            ClipassError::Io(err) => write!(f, "io error: {}", err),
            ClipassError::IdExists(id) => write!(f, "id exists already: {id}"),
            ClipassError::Input(input) => write!(f, "input error: {input}")
        }
    }
}

impl std::error::Error for ClipassError {}

impl From<std::io::Error> for ClipassError {
    fn from(value: Error) -> Self {
        ClipassError::Io(value)
    }
}

impl From<ClipassError> for std::io::Error {
    fn from(value: ClipassError) -> Self {
        match value {
            ClipassError::Io(err)
                => err,
            ClipassError::InvalidCommand(cmd)
                => Error::new(ErrorKind::NotFound, format!("{cmd}")),
            ClipassError::NotFound
                => Error::new(ErrorKind::NotFound, "Not found".to_string()),
            ClipassError::IdExists(id)
                => Error::new(ErrorKind::InvalidInput, format!("{id}")),
            ClipassError::Input(input)
                => Error::new(ErrorKind::InvalidInput, format!("input error: {input}"))
        }
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