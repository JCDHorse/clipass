use std::fs;
use std::path::Path;
use crate::command::Command;
use crate::error::ClipassError;
use crate::utils::input_read;
use crate::vault::Vault;

pub struct Clipass {
    cli_on: bool,
    vault: Vault,
    path: String,
}

impl Clipass {
    pub fn new() ->  Result<Self, ClipassError> {
        let path = String::from("test.json");
        let vault: Vault;
        if Path::new(&path).exists() {
            let pass: String = input_read("password: ")?;
            vault = Vault::load_from_file(pass.as_str(), path.as_str()).unwrap()
        }
        else {
            vault = Vault::new(None);
        }
        Ok(Self { cli_on: false, vault, path })
    }

    pub fn command_line(&mut self) {
        println!("clipass 0.0.1");
        println!("help to show available commands");
        self.cli_on = true;
        while self.cli_on {
            let cmd: Command = match input_read("> ") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}");
                    continue;
                }
            };
            let res = match self.run(cmd) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    continue;
                }
            };
            println!("{res}")
        }
    }

    pub fn run(&mut self, command: Command) -> Result<String, ClipassError> {
        match command {
            Command::Help => self.help(),
            Command::Get(id) => {
                let e = self.get(&id)?.to_string();
                Ok(e)
            },
            Command::New => self.new_entry(),
            Command::List => self.list(),
            Command::Save => self.save(),
            Command::Quit => self.quit(),
        }
    }

    // List all commands
    pub fn help(&self) -> Result<String, ClipassError> {
        let help_str =
            "commands: \n\
            \t- list: list all entries\n\
            \t- get <id>: get entry by id\n\
            \t- new: new entry\n\
            \t- save: save to file\n\
            \t- help: show this help\n\
            \t- quit";
        Ok(help_str.to_string())
    }

    pub fn list(&self) -> Result<String, ClipassError> {
        let mut listing = String::new();
        for entry in self.vault.get_all() {
            listing.push_str(format!("- {}: ******\n", entry.0).as_str());
        }
        Ok(listing.to_string())
    }

    pub fn get(&self, id: &String) -> Result<&String, ClipassError> {
        Ok(self.vault.get_value(id)?)
    }

    pub fn new_entry(&mut self) -> Result<String, ClipassError> {
        let id: String = input_read("id: ")?;

        if self.vault.contains_key(&id) {
            return Err(ClipassError::IdExists(id));
        }

        let value: String = input_read("value: ")?;

        self.vault.new_entry(&id, &value)?;
        Ok(format!("{id}"))
    }

    pub fn quit(&mut self) -> Result<String, ClipassError> {
        self.save()?;
        self.cli_on = false;
        Ok("".to_string())
    }

    pub fn save(&mut self) -> Result<String, ClipassError> {
        let pass: String= input_read("password: ")?;
        match self.vault.crypt_to_file(pass.as_str(), self.path.as_str()) {
            Ok(_) => {},
            Err(err) => return Err(ClipassError::NotFound),
        }
        Ok("saved".to_string())
    }
}