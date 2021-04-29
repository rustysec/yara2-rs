use yara2::*;

pub fn main() -> Result<()> {
    let pe = r#"
rule is_pe
{
meta:
      description = "checks if it is a pe process"
      author = "Russ"
      date = "2020-12-18"
strings:
    $pe = "MZ"
condition:
    $pe
}"#;

    let elf = r#"
rule is_elf
{
meta:
    description = "checks if it is an elf process"
    author = "Russ"
    date = "2020-12-18"
strings:
    $elf = "ELF"
condition:
    $elf
}"#;

    let mut yara = Yara::new()?;
    yara.add_rule_str(pe.trim(), None)?;
    yara.add_rule_str(elf.trim(), None)?;
    let results = yara.scan_process(
        std::env::args()
            .nth(1)
            .expect("please provide a pid to scan")
            .parse()
            .expect("not a valid pid"),
    )?;

    println!("results: {:?}", results);
    Ok(())
}
