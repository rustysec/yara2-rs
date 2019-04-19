#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
extern crate lazy_static;
extern crate err_derive;
extern crate serde;

mod bindings;
mod callbacks;
mod errors;
mod libyara;
mod rule;
mod yara;

pub use errors::*;
pub use rule::*;
pub use yara::*;
