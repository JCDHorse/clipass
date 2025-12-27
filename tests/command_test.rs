use std::str::FromStr;
use clipass::command::Command;

#[test]
fn parse_get_command_with_arg() {
    let cmd = Command::from_str("get myid").expect("parse ok");
    match cmd {
        Command::Get(arg) => assert_eq!(arg, "myid"),
        _ => panic!("expected Get variant"),
    }
}

#[test]
fn parse_help_and_list() {
    assert!(matches!(Command::from_str("help").unwrap(), Command::Help));
    assert!(matches!(Command::from_str("list").unwrap(), Command::List));
    assert!(matches!(Command::from_str("new").unwrap(), Command::New));
}