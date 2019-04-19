use crate::bindings;
use crate::rule::get_tidx;
use serde::Serialize;
use std::ffi::CStr;
use std::marker;

#[derive(Clone, Debug, Serialize)]
pub struct Match {
    /// Offset of the match within the scanning area.
    pub offset: usize,
    /// Length of the file. Can be useful if the matcher string has not a fixed length.
    pub length: usize,
    /// Matched data.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct YrString {
    /// Name of the string, with the '$'.
    pub identifier: String,
    /// Matches of the string for the scan.
    pub matches: Vec<Match>,
}

pub struct YrStringIterator<'a> {
    head: *const bindings::YR_STRING,
    _marker: marker::PhantomData<&'a bindings::YR_STRING>,
}

impl<'a> From<&bindings::YR_RULE> for YrStringIterator<'a> {
    fn from(rule: &bindings::YR_RULE) -> YrStringIterator<'a> {
        YrStringIterator {
            head: rule.get_strings(),
            _marker: marker::PhantomData::default(),
        }
    }
}

impl<'a> Iterator for YrStringIterator<'a> {
    type Item = &'a bindings::YR_STRING;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        let string = unsafe { &*self.head };

        if string.g_flags as u32 & bindings::STRING_GFLAGS_NULL != 0 {
            None
        } else {
            self.head = unsafe { self.head.offset(1) };
            Some(string)
        }
    }
}

impl From<&bindings::YR_STRING> for YrString {
    fn from(string: &bindings::YR_STRING) -> Self {
        let identifier = unsafe { CStr::from_ptr(string.get_identifier()) }
            .to_str()
            .unwrap()
            .to_owned();
        let tidx = get_tidx();
        let matches = MatchIterator::from(&string.matches[tidx as usize])
            .map(Match::from)
            .collect();

        YrString {
            identifier,
            matches,
        }
    }
}

pub struct MatchIterator<'a> {
    head: *const bindings::YR_MATCH,
    _marker: marker::PhantomData<&'a bindings::YR_MATCH>,
}

impl<'a> From<&'a bindings::YR_MATCHES> for MatchIterator<'a> {
    fn from(matches: &'a bindings::YR_MATCHES) -> MatchIterator<'a> {
        MatchIterator {
            head: matches.get_head(),
            _marker: marker::PhantomData::default(),
        }
    }
}

impl<'a> Iterator for MatchIterator<'a> {
    type Item = &'a bindings::YR_MATCH;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.head.is_null() {
            let m = unsafe { &*self.head };
            self.head = m.next;
            Some(m)
        } else {
            None
        }
    }
}

impl<'a> From<&'a bindings::YR_MATCH> for Match {
    fn from(m: &bindings::YR_MATCH) -> Self {
        Match {
            offset: m.offset as usize,
            length: m.match_length as usize,
            data: Vec::from(unsafe { std::slice::from_raw_parts(m.data, m.data_length as usize) }),
        }
    }
}
