use std::io;
use std::io::{Read, Write};
use std::str::FromStr;
use crate::error::ClipassError;

pub fn input_read<T>(ask_msg: &str) -> Result<T, ClipassError>
where
    T: FromStr, // The return type need to be cast from a str
    // The return error can be converted from io::Error for flush and from T::Err for parse
    ClipassError: From<io::Error> + From<T::Err>,
    <T as FromStr>::Err: std::fmt::Display,
{
    input_read_with(ask_msg, &mut io::stdin(), &mut io::stdout())
}

pub fn input_read_with<T, R, W>(ask_msg: &str, reader: &mut R, writer: &mut W) -> Result<T, ClipassError>
where
    T: FromStr,
    R: Read,
    W: Write,
    <T as FromStr>::Err: std::fmt::Display,
{
    use std::io::BufRead;
    let mut buf_reader = io::BufReader::new(reader);
    loop {
        let mut line = String::new();
        writer.write_all(ask_msg.as_bytes())?;
        writer.flush()?;
        buf_reader.read_line(&mut line)?;
        writer.flush()?;
        match line.trim().parse() {
            Ok(v) => return Ok(v),
            Err(e) => eprintln!("invalid input {} ({})", line.trim(), e),
        }
    }
}