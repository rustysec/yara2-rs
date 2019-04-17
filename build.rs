use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").expect("TARGET was not set");

    if cfg!(feature = "static") {
        if !Path::new("yara/.git").exists() {
            let _ = Command::new("git")
                .args(&["submodule", "update", "--init"])
                .status();
        }

        if !Path::new("yara/libyara/.libs").exists() {
            let mut args = vec!["--without-crypto"];

            if target.contains("musl") {
                env::set_var("CC", "musl-gcc");
            }

            if target.contains("windows-gnu") {
                if target.contains("x86_64") {
                    args.push("--host=x86_64-w64-mingw32");
                } else {
                    args.push("--host=i686-w64-mingw32");
                }
            }

            Command::new("./bootstrap.sh")
                .current_dir("./yara")
                .output()
                .unwrap();

            Command::new("./configure")
                .args(&args)
                .current_dir("./yara")
                .output()
                .unwrap();

            Command::new("make").current_dir("./yara").output().unwrap();
        }

        println!("cargo:rustc-link-lib=static=yara");
        println!("cargo:rustc-link-search=./yara/libyara/.libs");
    } else {
        println!("cargo:rustc-link-lib=yara");
    }
}
