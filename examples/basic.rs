extern crate yara2;

use yara2::*;

pub fn main() -> Result<()> {
    println!("Yara basic usage example");
    let rule = r#"rule is_awesome {
  strings:
    $rust = "rust" nocase

  condition:
    $rust
}"#;
    let mut yara = Yara::new()?;
    yara.add_rule_str(rule, None)?;
    println!("no matches:   {:?}", yara.scan_memory(b"this is a string")?);
    println!(
        "some matches: {:?}",
        yara.scan_memory(b"this is a rust string")?
    );
    Ok(())
}
