use std::str::FromStr;
use crate::error::ClipassError;

pub enum Command {
    Help,
    List,
    Get(String),
    New,
    Save,
    Quit,
}

impl FromStr for Command {
    type Err = ClipassError;

    // Implementing the command handling
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.trim().split_whitespace();
        let cmd_name = parts.next()
            .ok_or(ClipassError::InvalidCommand("Empty".to_string()))?;

        match cmd_name {
            "help" => Ok(Command::Help),
            "get" => {
                let arg = parts.next()
                    .ok_or(ClipassError::InvalidCommand("missing argument for 'get'".to_string()))?;
                Ok(Command::Get(arg.to_string()))
            },
            "list" => Ok(Command::List),
            "new" => Ok(Command::New),
            "save" => Ok(Command::Save),
            "quit" => Ok(Command::Quit),
            _ => Err(ClipassError::InvalidCommand(cmd_name.to_string()))
        }
    }
}