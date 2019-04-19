use crate::bindings;
use serde::Serialize;
use std::ffi::CStr;
use std::marker;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Metadata {
    pub identifier: String,
    pub value: MetadataValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum MetadataValue {
    Integer(i64),
    String(String),
    Boolean(bool),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaType {
    Null,
    Integer,
    String,
    Boolean,
}

impl MetaType {
    pub fn from_code(code: i32) -> Result<Self, i32> {
        use self::MetaType::*;
        match code as u32 {
            bindings::META_TYPE_NULL => Ok(Null),
            bindings::META_TYPE_INTEGER => Ok(Integer),
            bindings::META_TYPE_STRING => Ok(String),
            bindings::META_TYPE_BOOLEAN => Ok(Boolean),
            _ => Err(code),
        }
    }
}

pub struct MetadataIterator<'a> {
    head: *const bindings::YR_META,
    _marker: marker::PhantomData<&'a bindings::YR_STRING>,
}

impl<'a> From<&bindings::YR_RULE> for MetadataIterator<'a> {
    fn from(rule: &bindings::YR_RULE) -> Self {
        MetadataIterator {
            head: rule.get_metas(),
            _marker: Default::default(),
        }
    }
}

impl<'a> Iterator for MetadataIterator<'a> {
    type Item = Metadata;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.head.is_null() {
            let meta = unsafe { &*self.head };
            let t = MetaType::from_code(meta.type_).unwrap();
            if t != MetaType::Null {
                self.head = unsafe { self.head.offset(1) };
                return Some(Metadata::from(meta));
            }
        }

        None
    }
}

impl From<&bindings::YR_META> for Metadata {
    fn from(meta: &bindings::YR_META) -> Self {
        let identifier = unsafe { CStr::from_ptr(meta.get_identifier()) }
            .to_str()
            .unwrap()
            .to_owned();
        let t = MetaType::from_code(meta.type_).unwrap();
        let value = match t {
            MetaType::Boolean => MetadataValue::Boolean(meta.integer != 0),
            MetaType::Integer => MetadataValue::Integer(meta.integer),
            MetaType::String => MetadataValue::String(
                unsafe { CStr::from_ptr(meta.get_string()) }
                    .to_str()
                    .unwrap()
                    .to_owned(),
            ),
            MetaType::Null => unreachable!(),
        };
        Metadata { identifier, value }
    }
}
