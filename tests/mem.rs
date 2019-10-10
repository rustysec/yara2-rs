extern crate yara2;

use yara2::*;

#[test]
fn yara_mem() {
    println!("Yara basic usage example");
    let rule = r#"rule is_awesome : tag1 tag2 {
  meta:
    an_integer = 42
    a_bool = true
    a_string = "a string"

  strings:
    $rust = "rust" nocase

  condition:
    $rust
}"#;
    let mut yara = Yara::new().expect("Couldn't init yara");
    yara.add_rule_str(rule, None).expect("Couldn't add rule");
    let none = yara
        .scan_memory(b"this is a string")
        .expect("error scanning memory!");
    let some = yara
        .scan_memory(b"this is a rust string")
        .expect("error scanning memory!");

    println!("no results:   {:?}", none);
    println!("some results: {:?}", some);
    assert!(none.len() == 0);
    assert!(some.len() != 0);
}
