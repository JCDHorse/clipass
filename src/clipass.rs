use std::path::Path;
use rpassword;
use rpassword::prompt_password;
use crate::command::Command;
use crate::error::ClipassError;
use crate::utils::input_read;
use crate::vault::vault::Vault;

const CLIPASS_VERSION: &str = "0.3.0-alpha";

pub struct Clipass {
    cli_on: bool,
    vault: Vault,
    path: String,
}

impl Clipass {
    pub fn new(path: &str) ->  Result<Self, ClipassError> {
        println!("clipass v{CLIPASS_VERSION}");
        let vault: Vault;
        let pass: String = prompt_password("password: ")?;
        if Path::new(&path).exists() {
            vault = Vault::load_from_file(pass.as_str(), path)?;
        }
        else {
            vault = Vault::new_empty(pass.as_str())?;
        }
        Ok(Self { cli_on: false, vault, path: path.to_string() })
    }

    pub fn command_line(&mut self) {
        println!("vault created at:\t\t{}", self.vault.created_at().format("%c"));
        println!("vault modified at:\t\t{}", self.vault.modified_at().format("%c"));
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
            Command::Update(id) => self.update(&id),
            Command::Delete(id) => self.delete(&id),
            Command::New => self.new_entry(),
            Command::List => self.list(),
            Command::Save => self.save(),
            Command::Quit => self.quit(),
        }
    }

    // List all commands
    pub fn help(&self) -> Result<String, ClipassError> {
        static HELP_STR: &str =
            "commands: \n\
            \r  - list: list all entries\n\
            \r  - new: new entry\n\
            \r  - get <id>: get entry by id\n\
            \r  - update <id>\n\
            \r  - delete <id> \n\
            \r  - save: save to file\n\
            \r  - help: show this help\n\
            \r  - quit";
        Ok(HELP_STR.to_string())
    }

    pub fn list(&self) -> Result<String, ClipassError> {
        let mut listing = String::new();
        for entry in self.vault.get_all() {
            listing.push_str(format!(" - {}: ******\n", entry.0).as_str());
        }
        Ok(listing.to_string())
    }

    pub fn get(&self, id: &String) -> Result<&String, ClipassError> {
        Ok(self.vault.get_value(id)?)
    }

    pub fn update(&mut self, id: &String) -> Result<String, ClipassError> {
        if !self.vault.contains_key(id) {
            return Err(ClipassError::NotFound(id.clone()));
        }
        let new_value: String = input_read("new value: ")?;
        self.vault.update(id, new_value.as_str())?;
        Ok(format!("updated {id}"))
    }

    pub fn delete(&mut self, id: &String) -> Result<String, ClipassError> {
        self.vault.delete_entry(id)?;
        Ok(format!("deleted {id}"))
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
        self.vault.crypt_to_file(self.path.as_str())?;
        Ok("saved".to_string())
    }
}