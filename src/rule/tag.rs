use crate::bindings;
use std::ffi::CStr;
use std::marker;
use std::os::raw::c_char;

pub struct TagIterator<'a> {
    head: *const c_char,
    _marker: marker::PhantomData<&'a c_char>,
}

impl<'a> From<&'a bindings::YR_RULE> for TagIterator<'a> {
    fn from(rule: &bindings::YR_RULE) -> Self {
        TagIterator {
            head: rule.get_tags(),
            _marker: Default::default(),
        }
    }
}

impl<'a> Iterator for TagIterator<'a> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.head.is_null() && unsafe { *self.head } != 0 {
            let s = unsafe { CStr::from_ptr(self.head) };
            self.head = unsafe { self.head.add(s.to_bytes_with_nul().len()) };
            Some(s.to_str().unwrap().to_owned())
        } else {
            None
        }
    }
}
