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

    let path= match args.get(1) {
        Some(p) => p.clone(),
        None => utils::input_read("vault path: ")?,
    };

    let mut clipass = Clipass::new(path.as_str())?;
    clipass.command_line();
    Ok(())
}
