extern crate bindgen;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let target = env::var("TARGET").expect("TARGET was not set");

    if cfg!(feature = "with-bindgen") {
        let bindings = bindgen::Builder::default()
            // The input header we would like to generate
            // bindings for.
            .header("yara/libyara/include/yara.h")
            .whitelist_type("YR_RULE")
            .whitelist_var("META_TYPE_.*")
            .whitelist_var("STRING_GFLAGS_NULL")
            .whitelist_function("yr_get_tidx")
            .whitelist_function("yr_initialize")
            .whitelist_function("yr_finalize")
            .whitelist_function("yr_rules_destroy")
            .whitelist_function("yr_rules_scan_mem")
            .whitelist_function("yr_compiler_add_string")
            .whitelist_function("yr_compiler_create")
            .whitelist_function("yr_compiler_destroy")
            .whitelist_function("yr_compiler_get_rules")
            .clang_arg("yara/libyara/include/yara")
            .trust_clang_mangling(false)
            // Finish the builder and generate the bindings.
            .generate()
            // Unwrap the Result and panic on failure.
            .expect("Unable to generate bindings");
        let out_path = PathBuf::from("src").join("bindings.rs");
        let data = bindings
            .to_string()
            .replacen("match_:", "match__:", 1)
            .replacen("match:", "match_", 1)
            .replace("_YR_MATCH", "YR_MATCH");
        let mut file = File::create(out_path).expect("couldn't open file!");
        file.write_all(data.as_bytes())
            .expect("couldn't write bindings.rs!");
    }

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
