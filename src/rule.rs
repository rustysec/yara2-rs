use std::ffi::CStr;

#[derive(Debug, Default)]
pub struct Rule {
    pub identifier: String,
    pub namespace: String,
    //pub metadata: Metadata,
    //pub tags: Tags,
    //pub strings: Strings,
}

impl From<&yara_sys::YR_RULE> for Rule {
    fn from(rule: &yara_sys::YR_RULE) -> Self {
        let id = unsafe {
            CStr::from_ptr(rule.get_identifier())
                .to_str()
                .unwrap()
                .to_owned()
        };
        Rule {
            identifier: id,
            ..Default::default()
        }
    }
}
