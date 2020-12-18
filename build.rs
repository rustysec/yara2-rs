#[cfg(feature = "with-bindgen")]
extern crate bindgen;

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
            .whitelist_function("yr_rules_scan_proc")
            .whitelist_function("yr_compiler_add_string")
            .whitelist_function("yr_compiler_create")
            .whitelist_function("yr_compiler_destroy")
            .whitelist_function("yr_compiler_get_rules")
            .whitelist_function("yr_compiler_set_callback")
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
        }

        let target = std::env::var("TARGET").unwrap();

        let mut build = static_compile_get_files();

        if target.contains("windows") {
            println!("Building Windows");
            build
                .file("./yara/libyara/modules/hash.c")
                .define("_FILE_OFFSET_BITS", Some("64"))
                .define("STDC_HEADERS", Some("1"))
                .define("HAVE_SYS_TYPES_H", Some("1"))
                .define("HAVE_SYS_STAT_H", Some("1"))
                .define("HAVE_STDLIB_H", Some("1"))
                .define("HAVE_STRING_H", Some("1"))
                .define("HAVE_MEMORY_H", Some("1"))
                .define("HAVE_STRINGS_H", Some("1"))
                .define("HAVE_INTTYPES_H", Some("1"))
                .define("HAVE_STDINT_H", Some("1"))
                .define("HAVE_UNISTD_H", Some("1"))
                .define("HAVE_LIBM", Some("1"))
                .define("HAVE_LIBM", Some("1"))
                .define("HAVE__MKGMTIME", None)
                .define("HAVE_WINCRYPT_H", Some("1"))
                .define("HAVE_STDBOOL_H", Some("1"))
                .define("HAVE_CLOCK_GETTIME", Some("1"))
                .define("HAVE_SCAN_PROC_IMPL", Some("1"))
                .define("USE_WINDOWS_PROC", None)
                .define("HASH_MODULE", None)
                .compile("libyara");
        } else if target.contains("apple") {
            println!("Building MacOS");
            build
                .define("YYTEXT_POINTER", Some("1"))
                .define("STDC_HEADERS", Some("1"))
                .define("HAVE_SYS_TYPES_H", Some("1"))
                .define("HAVE_SYS_STAT_H", Some("1"))
                .define("HAVE_STDLIB_H", Some("1"))
                .define("HAVE_STRING_H", Some("1"))
                .define("HAVE_MEMORY_H", Some("1"))
                .define("HAVE_STRINGS_H", Some("1"))
                .define("HAVE_INTTYPES_H", Some("1"))
                .define("HAVE_STDINT_H", Some("1"))
                .define("HAVE_UNISTD_H", Some("1"))
                .define("HAVE_DLFCN_H", Some("1"))
                .define("HAVE_LIBM", Some("1"))
                .define("HAVE_MEMMEM", Some("1"))
                .define("HAVE_TIMEGM", Some("1"))
                .define("HAVE_STDBOOL_H", Some("1"))
                .define("HAVE_CLOCK_GETTIME", Some("1"))
                .define("HAVE_SCAN_PROC_IMPL", Some("1"))
                .define("USE_MACH_PROC", None)
                .compile("yara");
        } else {
            println!("Building Linux");
            build
                //.file("./yara/libyara/modules/magic.c")
                .define("YYTEXT_POINTER", Some("1"))
                .define("STDC_HEADERS", Some("1"))
                .define("HAVE_SYS_TYPES_H", Some("1"))
                .define("HAVE_SYS_STAT_H", Some("1"))
                .define("HAVE_STDLIB_H", Some("1"))
                .define("HAVE_STRING_H", Some("1"))
                .define("HAVE_MEMORY_H", Some("1"))
                .define("HAVE_STRINGS_H", Some("1"))
                .define("HAVE_INTTYPES_H", Some("1"))
                .define("HAVE_STDINT_H", Some("1"))
                .define("HAVE_UNISTD_H", Some("1"))
                .define("HAVE_DLFCN_H", Some("1"))
                .define("HAVE_LIBM", Some("1"))
                .define("HAVE_LIBM", Some("1"))
                .define("HAVE_MEMMEM", Some("1"))
                .define("HAVE_TIMEGM", Some("1"))
                .define("HAVE_STDBOOL_H", Some("1"))
                .define("HAVE_CLOCK_GETTIME", Some("1"))
                .define("HAVE_SCAN_PROC_IMPL", Some("1"))
                .define("USE_LINUX_PROC", None)
                .compile("libyara");
        }
    } else {
        println!("cargo:rustc-link-lib=yara");
        //println!("cargo:rustc-link-lib=ssl");
    }
}

fn make_it(it: &cc::Build) -> cc::Build {
    it.clone()
}

fn static_compile_get_files() -> cc::Build {
    make_it(
        cc::Build::new()
            .warnings(false)
            .file("./yara/libyara/arena.c")
            .file("./yara/libyara/re.c")
            .file("./yara/libyara/grammar.c")
            .file("./yara/libyara/atoms.c")
            .file("./yara/libyara/filemap.c")
            .file("./yara/libyara/hex_grammar.c")
            .file("./yara/libyara/exefiles.c")
            .file("./yara/libyara/ahocorasick.c")
            .file("./yara/libyara/rules.c")
            .file("./yara/libyara/endian.c")
            .file("./yara/libyara/compiler.c")
            .file("./yara/libyara/stack.c")
            .file("./yara/libyara/strutils.c")
            .file("./yara/libyara/stopwatch.c")
            .file("./yara/libyara/parser.c")
            .file("./yara/libyara/re_lexer.c")
            .file("./yara/libyara/exec.c")
            .file("./yara/libyara/hex_lexer.c")
            .file("./yara/libyara/stream.c")
            .file("./yara/libyara/threading.c")
            .file("./yara/libyara/bitmask.c")
            .file("./yara/libyara/object.c")
            .file("./yara/libyara/proc.c")
            .file("./yara/libyara/sizedstr.c")
            .file("./yara/libyara/scan.c")
            .file("./yara/libyara/scanner.c")
            .file("./yara/libyara/lexer.c")
            .file("./yara/libyara/mem.c")
            .file("./yara/libyara/modules.c")
            .file("./yara/libyara/re_grammar.c")
            .file("./yara/libyara/proc/none.c")
            .file("./yara/libyara/proc/linux.c")
            .file("./yara/libyara/proc/mach.c")
            .file("./yara/libyara/proc/windows.c")
            .file("./yara/libyara/proc/openbsd.c")
            .file("./yara/libyara/proc/freebsd.c")
            .file("./yara/libyara/libyara.c")
            .file("./yara/libyara/hash.c")
            //.file("./yara/libyara/modules/cuckoo.c")
            .file("./yara/libyara/modules/elf.c")
            .file("./yara/libyara/modules/macho.c")
            .file("./yara/libyara/modules/pe.c")
            .file("./yara/libyara/modules/pe_utils.c")
            .file("./yara/libyara/modules/math.c")
            .file("./yara/libyara/modules/tests.c")
            .file("./yara/libyara/modules/dex.c")
            .file("./yara/libyara/modules/dotnet.c")
            .file("./yara/libyara/modules/demo.c")
            //.file("./yara/libyara/modules/magic.c")
            .file("./yara/libyara/modules/time.c")
            //.file("./yara/libyara/modules/hash.c")
            .include("./yara")
            .include("./yara/libyara")
            .include("./yara/libyara/include")
            .static_flag(true),
    )
}
