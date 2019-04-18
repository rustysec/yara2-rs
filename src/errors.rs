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
    #[error(display = "Unknown yara error: {}", _0)]
    UnknownYaraError(i32),
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
