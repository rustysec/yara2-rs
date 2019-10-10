extern crate yara2;

use yara2::*;

#[test]
fn test_yara_file() {
    let rule = r#"rule has_flag {

  strings:
    $flag = "FLAG"

  condition:
    $flag
}"#;
    let mut yara = Yara::new().expect("Could not initiate yara!");
    yara.add_rule_str(rule, None).expect("Could not load rule!");
    let none = yara.scan_file("./tests/data1.txt");
    let some = yara.scan_file("./tests/data2.txt");

    println!("no results:   {:?}", none);
    println!("some results: {:?}", some);
    assert!(true)
}
