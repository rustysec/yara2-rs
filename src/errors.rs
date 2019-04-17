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
    #[error(display = "Unknown yara error")]
    UnknownYaraError(yara_sys::Error),
}

impl From<yara_sys::Error> for Error {
    fn from(error: yara_sys::Error) -> Self {
        Error::UnknownYaraError(error)
    }
}
