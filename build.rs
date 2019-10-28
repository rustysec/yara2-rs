#[cfg(feature = "with-bindgen")]
extern crate bindgen;

use std::env;
#[cfg(feature = "with-bindgen")]
use std::fs::File;
#[cfg(feature = "with-bindgen")]
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;

fn main() {
    #[cfg(feature = "with-bindgen")]
    {
        use std::path::PathBuf;

        if !Path::new("yara/.git").exists() {
            let _ = Command::new("git")
                .args(&["submodule", "update", "--init"])
                .status();
        }

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
            .whitelist_function("yr_rules_scan_fd")
            .whitelist_function("yr_compiler_add_string")
            .whitelist_function("yr_compiler_create")
            .whitelist_function("yr_compiler_destroy")
            .whitelist_function("yr_compiler_get_rules")
            .clang_arg("-I./yara/libyara/include")
            .trust_clang_mangling(false)
            // disable layout tests due to cross platform requirements
            .layout_tests(false)
            // format the output
            .rustfmt_bindings(true)
            // Finish the builder and generate the bindings.
            .generate()
            // Unwrap the Result and panic on failure.
            .expect("Unable to generate bindings");
        let out_path = PathBuf::from("src").join("bindings.rs");
        let data = bindings
            .to_string()
            .replacen("match_:", "match__:", 1)
            .replacen("match:", "match_", 1)
            .replacen("pe_:", "pe__:", 1)
            .replacen("pe:", "pe_", 1)
            .replace("_YR_MATCH", "YR_MATCH")
            .replace(
                "pub match_: *mut YR_AC_MATCH",
                "pub match__: *mut YR_AC_MATCH",
            );
        let mut file = File::create(out_path).expect("couldn't open file!");
        file.write_all(data.as_bytes())
            .expect("couldn't write bindings.rs!");
    }

    if cfg!(feature = "static") {
        if !Path::new("yara/.git").exists() {
            let _ = Command::new("git")
                .args(&["submodule", "update", "--init"])
                .status();
        } else {
            let _clean = Command::new("make")
                .args(&["clean"])
                .current_dir("./yara")
                .output()
                .expect("Cannot clean yara folder");

            let _distclean = Command::new("make")
                .args(&["distclean"])
                .current_dir("./yara")
                .output()
                .expect("Cannot distclean yara folder");
        }

        let mut args = vec![
            String::from("--without-crypto"),
            String::from("--enable-static"),
            String::from("--disable-shared"),
            String::from("--with-pic"),
        ];

        if let Ok(cross_host) = env::var("CROSS_HOST") {
            args.push(format!("--host={}", cross_host));
        }

        Command::new("./bootstrap.sh")
            .current_dir("./yara")
            .output()
            .expect("Cannot bootstrap yara folder");

        Command::new("./configure")
            .args(&args)
            .current_dir("./yara")
            .output()
            .expect("Cannot configure yara!");

        Command::new("make")
            .current_dir("./yara")
            .output()
            .expect("Cannot make yara!");

        println!("cargo:rustc-link-lib=static=yara");
        println!("cargo:rustc-link-search=./yara/libyara/.libs");
    } else {
        println!("cargo:rustc-link-lib=yara");
    }
}
