use std::{
    collections::VecDeque,
    os::raw::c_void,
    sync::{Arc, Mutex},
};

lazy_static! {
    pub static ref LAST_ERROR: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, err_derive::Error)]
pub enum Error {
    #[error(display = "Rules have already been compiled")]
    AlreadyCompiled,
    #[error(display = "Callback error")]
    CallbackError,
    #[error(display = "Invalid rule syntax")]
    InvalidRule,
    #[error(display = "Too many rules")]
    TooManyRules,
    #[error(display = "Cannot open file: {}", _0)]
    InvalidFile(String),
    #[error(display = "Unknown yara error: {}", _0)]
    UnknownYaraError(i32),
    #[error(display = "Multiple yara errors")]
    Multiple(Vec<String>),
}

impl From<i32> for Error {
    fn from(error: i32) -> Self {
        Error::UnknownYaraError(error)
    }
}

impl Error {
    pub fn from_code(code: i32) -> Result<()> {
        match code {
            0 => Ok(()),
            _ => Err(Error::from(code)),
        }
    }
}

/// Callback reached when something goes wrong
///
/// # Safety
/// This function converts string pointers and uses unsafe code
pub unsafe extern "C" fn error_callback(
    _level: i32,
    _file_name: *const i8,
    _line_number: i32,
    _message: *const i8,
    _user_data: *mut c_void,
) {
    use std::ffi::CStr;
    let message = CStr::from_ptr(_message)
        .to_str()
        .map(|s| s.to_string())
        .unwrap_or_default();

    (LAST_ERROR.lock().unwrap()).push_back(format!("Line {}: {}", _line_number, message));
}

/// Retrieves the last error message from Yara
pub fn get_last_error() -> Option<String> {
    let mut lock = LAST_ERROR.lock().unwrap();
    lock.pop_front()
}
