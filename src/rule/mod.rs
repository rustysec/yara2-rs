mod metadata;
mod tag;
mod yr_string;

use self::metadata::*;
use self::tag::*;
use self::yr_string::*;
use crate::bindings;
use serde::Serialize;
use std::ffi::CStr;

#[derive(Clone, Debug, Serialize)]
pub struct Rule {
    pub identifier: String,
    pub namespace: String,
    pub metadata: Vec<Metadata>,
    pub tags: Vec<String>,
    pub strings: Vec<YrString>,
}

impl From<&bindings::YR_RULE> for Rule {
    fn from(rule: &bindings::YR_RULE) -> Self {
        let id = unsafe {
            CStr::from_ptr(rule.get_identifier())
                .to_str()
                .unwrap()
                .to_owned()
        };
        let ns = unsafe { CStr::from_ptr((&*rule.get_ns()).get_name()) }
            .to_str()
            .unwrap()
            .to_owned();
        Rule {
            identifier: id,
            namespace: ns,
            tags: TagIterator::from(rule).collect(),
            metadata: MetadataIterator::from(rule).collect(),
            strings: YrStringIterator::from(rule)
                .map(|s| YrString::from(s))
                .collect(),
        }
    }
}

/// Get the Yara thread id.
fn get_tidx() -> i32 {
    unsafe { bindings::yr_get_tidx() }
}
