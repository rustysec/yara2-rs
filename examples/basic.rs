extern crate yara2;

use yara2::*;

pub fn main() -> Result<()> {
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
    let mut yara = Yara::new()?;
    yara.add_rule_str(rule, None)?;
    let none = yara.scan_memory(b"this is a string")?;
    let some = yara.scan_memory(b"this is a rust string")?;

    println!("no results:   {:?}", none);
    println!("some results: {:?}", some);
    Ok(())
}
