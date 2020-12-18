yara2
=====
[![Build Status](https://github.com/rustysec/yara2-rs/workflows/Build/badge.svg)](https://github.com/rustysec/yara2-rs/actions)

Simple rust bindings bindings for [yara](https://github.com/VirusTotal/yara).
A lot of implementation details were borrowed from/inspired by
[yara-rust](https://github.com/Hugal31/yara-rust) with some minor differences.
This library does not aim to have 100% of the API surface of libyara, but provide
an easily consumable interface to it.

This library is under active development and, as such, is still a work in progress.
It is currently not feature complete. Some features targeted:

- [ ] Loading signatures from file system
- [X] Scanning files, instead of just data blobs
- [X] Scanning running processes
- [ ] Multi-threading option

## Usage
Everything begins with the `Yara` structure, from there it is simple:

```rust
extern crate yara2;

let mut yara = yara2::Yara::new().unwrap();
```

Adding rules is a simple process:

```rust
yara.add_rule_str(r#"rule is_awesome {
strings:
    $rust = "rust" nocase

condition:
    $rust
}"#, None).unwrap();
```

Then you can scan some data:

```rust
let matches = yara.scan_memory(b"data blob containing rust signature");
```

## Cross Compiling
If you're using [osxcross](https://github.com/tpoechtrager/osxcross) it might be helpful to pass the
`CC` environmental variable to ensure cargo picks the right one.

```sh
CC=x86_64-apple-darwin19-cc cargo build --examples
```

## About
This crate does contain unsafe code, but efforts are taken to try and ensure
it will not cause runtime errors. The default behavior is to statically link
to `libyara` at compile time. If this behavior is not desired, dynamic linking
can be enabled:

```toml
[dependencies]
yara2 = { git = "https://github.com/rustysec/yara2-rs", features = ["dynamic"], default-features = false }
```

## License

Licensed under [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT
