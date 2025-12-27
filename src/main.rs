use crate::clipass::Clipass;
use crate::error::ClipassError;

use std::env;

mod command;
mod crypto;
mod error;
mod clipass;
mod utils;
mod vault;

fn main() -> Result<(), ClipassError> {
    let args: Vec<String> = env::args().collect();
    let mut clipass = Clipass::new()?;
    clipass.command_line();
    Ok(())
}
