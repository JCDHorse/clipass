use crate::clipass::Clipass;
use crate::error::ClipassError;

mod command;
mod error;
mod clipass;
mod utils;
mod vault;

fn main() -> Result<(), ClipassError> {
    let mut clipass = Clipass::new()?;
    clipass.command_line();
    Ok(())
}
