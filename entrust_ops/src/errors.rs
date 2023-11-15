//! A convenient [`Error`] type.
use std::fmt;

/// A convenient error type for errors that don't need to be inspected
/// programmatically.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl<E: std::error::Error> From<E> for Error {
    fn from(error: E) -> Self {
        Self::new(error.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}
