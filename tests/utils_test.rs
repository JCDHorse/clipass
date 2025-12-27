use clipass::utils;
#[test]
fn test_input_read_with() {
    use std::io::Cursor;
    let mut input = Cursor::new("42\n".as_bytes());
    let mut output = Vec::new();
    let value: i32 = utils::input_read_with("prompt: ", &mut input, &mut output).unwrap();
    assert_eq!(value, 42);
    let out_str = String::from_utf8(output).unwrap();
    assert!(out_str.contains("prompt: "));
}