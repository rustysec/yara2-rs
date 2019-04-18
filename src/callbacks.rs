use crate::Rule;
use std::os::raw::{c_int, c_void};

pub extern "C" fn scan_callback(
    msg: c_int,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> i32 {
    let rules = unsafe { &mut *(user_data as *mut Vec<Rule>) };
    if msg == 1 {
        let rule: crate::bindings::YR_RULE = unsafe { std::ptr::read(message_data as _) };
        rules.push(Rule::from(&rule));
    }
    0 // Callback Success
}
