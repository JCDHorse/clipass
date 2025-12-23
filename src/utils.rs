use std::fmt::Display;
use std::io;
use std::io::Write;
use std::str::FromStr;
use crate::error::ClipassError;

pub fn input_read<T>(ask_msg: &str) -> Result<T, ClipassError>
where
    T: FromStr, // The return type need to be cast from a str
    // The return error can be converted from io::Error for flush and from T::Err for parse
    ClipassError: From<io::Error> + From<T::Err>,
    <T as FromStr>::Err: std::fmt::Display
{
    loop {
        let mut line = String::new();
        print!("{}", ask_msg);
        io::stdout().flush()?;
        io::stdin().read_line(&mut line)?;
        io::stdout().flush()?;
        match line.trim().parse() {
            Ok(v) => return Ok(v),
            Err(e) => {
                eprintln!("invalid input {} ({})", line.trim(), e);
            }
        }
    }
}