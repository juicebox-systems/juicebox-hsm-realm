use std::error::Error;
use std::fmt::{self, Debug, Display};

use observability::metrics;

/// The error type returned by [`Retry`] loops.
///
/// `FE` stands for fatal error and `RE` stands for retryable error. While
/// using two distinct types can improve clarity and type safety, it's also
/// common for the same type to serve as both, distinguished at runtime by a
/// status code.
#[derive(Debug)]
pub enum RetryError<FE, RE = FE>
where
    FE: Debug,
    RE: Debug,
{
    /// An attempt returned a non-retryable error.
    Fatal { error: FE },

    /// The retry loop ran out of attempts or out of time, without completing a
    /// successful attempt or encountering a fatal error.
    Exhausted {
        /// The retryable error returned by the last completed attempt, unless
        /// no attempt completed before the deadline.
        last: Option<RE>,
    },
}

impl<FE, RE> RetryError<FE, RE>
where
    FE: Debug,
    RE: Debug,
{
    /// Convert from one fatal error type to another.
    pub fn map_fatal_err<FE2, F>(self, f: F) -> RetryError<FE2, RE>
    where
        F: Fn(FE) -> FE2,
        FE2: Debug,
    {
        match self {
            Self::Exhausted { last } => RetryError::Exhausted { last },
            Self::Fatal { error } => RetryError::Fatal { error: f(error) },
        }
    }

    /// Convert from one retryable error type to another.
    pub fn map_retryable_err<RE2, F>(self, f: F) -> RetryError<FE, RE2>
    where
        F: Fn(RE) -> RE2,
        RE2: Debug,
    {
        match self {
            Self::Exhausted { last: Some(last) } => RetryError::Exhausted {
                last: Some(f(last)),
            },
            Self::Exhausted { last: None } => RetryError::Exhausted { last: None },
            Self::Fatal { error } => RetryError::Fatal { error },
        }
    }
}

impl<FE, RE> Display for RetryError<FE, RE>
where
    FE: Debug + Display,
    RE: Debug + Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted { last: Some(last) } => {
                write!(f, "retries exhausted. last error: {last}")
            }
            Self::Exhausted { last: None } => write!(f, "retries exhausted. no attempts completed"),
            Self::Fatal { error } => Display::fmt(error, f),
        }
    }
}

impl<FE, RE> Error for RetryError<FE, RE>
where
    FE: Error,
    RE: Error,
{
}

/// Special case: when there's a single error type for both fatal and retryable
/// errors.
impl<E> RetryError<E, E>
where
    E: Debug,
{
    /// Return the error produced by the last attempt.
    ///
    /// Note that when the Retry loop is disabled, it will always complete a
    /// single attempt, so this will always return `Some`.
    pub fn last(self) -> Option<E> {
        match self {
            Self::Exhausted { last } => last,
            Self::Fatal { error } => Some(error),
        }
    }

    /// Convert from one combined error type to another.
    pub fn map_err<E2, F>(self, f: F) -> RetryError<E2, E2>
    where
        E2: Debug,
        F: Fn(E) -> E2,
    {
        match self {
            Self::Exhausted { last: Some(last) } => RetryError::Exhausted {
                last: Some(f(last)),
            },
            Self::Exhausted { last: None } => RetryError::Exhausted { last: None },
            Self::Fatal { error } => RetryError::Fatal { error: f(error) },
        }
    }
}

/// The error type returned by a single attempt within a [`Retry`] loop.
///
/// `FE` stands for fatal error and `RE` stands for retryable error. While
/// using two distinct types can improve clarity and type safety, it's also
/// common for the same type to serve as both, distinguished at runtime by a
/// status code.
#[derive(Debug)]
pub enum AttemptError<FE, RE = FE>
where
    FE: Debug,
    RE: Debug,
{
    /// An error occurred that should not be retried. The retry loop will
    /// immediately exit and propagate this error.
    Fatal {
        /// Fatal error.
        error: FE,
        /// Key-value pairs describing the `error` for use in metrics.
        tags: Vec<metrics::Tag>,
    },

    /// An error occurred that may be retried. The retry loop will try again,
    /// unless it has exhausted its budget.
    Retryable {
        /// Retryable error.
        error: RE,
        /// Key-value pairs describing the `error` for use in metrics.
        tags: Vec<metrics::Tag>,
    },
}

impl<FE, RE> AttemptError<FE, RE>
where
    FE: Debug,
    RE: Debug,
{
    /// Convert from one fatal error type to another.
    ///
    /// Note: The error will keep its original tags.
    pub fn map_fatal_err<FE2, F>(self, f: F) -> AttemptError<FE2, RE>
    where
        F: Fn(FE) -> FE2,
        FE2: Debug,
    {
        match self {
            Self::Fatal { error, tags } => AttemptError::Fatal {
                error: f(error),
                tags,
            },
            Self::Retryable { error, tags } => AttemptError::Retryable { error, tags },
        }
    }

    /// Convert from one retryable error type to another.
    ///
    /// Note: The error will keep its original tags.
    pub fn map_retryable_err<RE2, F>(self, f: F) -> AttemptError<FE, RE2>
    where
        F: Fn(RE) -> RE2,
        RE2: Debug,
    {
        match self {
            Self::Fatal { error, tags } => AttemptError::Fatal { error, tags },
            Self::Retryable { error, tags } => AttemptError::Retryable {
                error: f(error),
                tags,
            },
        }
    }
}

/// Special case: when there's a single error type for both fatal and retryable
/// errors.
impl<E> AttemptError<E, E>
where
    E: Debug,
{
    /// Convert from one combined error type to another.
    ///
    /// Note: The error will keep its original tags.
    pub fn map_err<E2, F>(self, f: F) -> AttemptError<E2, E2>
    where
        E2: Debug,
        F: Fn(E) -> E2,
    {
        match self {
            Self::Fatal { error, tags } => AttemptError::Fatal {
                error: f(error),
                tags,
            },
            Self::Retryable { error, tags } => AttemptError::Retryable {
                error: f(error),
                tags,
            },
        }
    }
}

/// An error type that serves as a placeholder when no fatal errors are
/// possible or have been defined.
///
/// This type is not instantiable.
#[derive(Debug)]
pub enum NoFatalErrors {}

impl Display for NoFatalErrors {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        unreachable!("NoFatalErrors cannot be instantiated")
    }
}

impl std::error::Error for NoFatalErrors {}
