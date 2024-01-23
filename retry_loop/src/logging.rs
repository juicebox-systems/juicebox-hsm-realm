use std::fmt::Debug;
use std::time::Duration;

use super::RetryError;
use observability::metrics;

/// Encodes what happened in the retry loop after an attempt.
///
/// This is normally used to emit log messages. Most users shouldn't care about
/// this and should use [`retry_logging!`].
#[derive(Debug)]
pub enum Event<'a, FE, RE>
where
    FE: Debug,
    RE: Debug,
{
    /// An attempt failed with a retryable error, and the retry loop will try
    /// again (after some backoff).
    Retrying {
        error: &'a RE,
        num_attempts: usize,
        last_attempt_duration: Duration,
        elapsed: Duration,
        backoff: Duration,
        overall_timeout: Duration,
        max_attempts: usize,
        tags: &'a [metrics::Tag],
        description: &'a str,
    },

    /// Either an attempt returned a fatal error, or the retry loop exhausted
    /// its budget (no more time or attempts remaining).
    Failed {
        error: &'a RetryError<FE, RE>,
        num_attempts: usize,
        elapsed: Duration,
        /// Note: If `max_attempts` was 0, this will be `Duration::ZERO`.
        last_attempt_duration: Duration,
        tags: &'a [metrics::Tag],
        description: &'a str,
    },

    /// An attempt (and the entry retry loop) succeeded with an `Ok` result.
    Succeeded {
        num_attempts: usize,
        elapsed: Duration,
        last_attempt_duration: Duration,
        tags: &'a [metrics::Tag],
        description: &'a str,
    },
}

/// This macro is used with [`Retry::retry`] to handle logging.
///
/// Use this version when the error types impl [`std::fmt::Display`].
/// Otherwise, use [`retry_logging_debug!`].
///
/// This is a macro rather than a function so that the call sites reported by
/// the logger (and suppressed by the logger) correspond to the many places the
/// retry loop is invoked, not the retry loop's single implementation.
#[macro_export]
macro_rules! retry_logging {
    () => {
        $crate::_retry_logging!(std::fmt::Display, tracing::field::display)
    };
}

/// This macro is used with [`Retry::retry`] to handle logging.
///
/// Use this version when the error types do not impl [`std::fmt::Display`].
/// Prefer [`retry_logging!`] otherwise.
///
/// This is a macro rather than a function so that the call sites reported by
/// the logger (and suppressed by the logger) correspond to the many places the
/// retry loop is invoked, not the retry loop's single implementation.
#[macro_export]
macro_rules! retry_logging_debug {
    () => {
        $crate::_retry_logging!(std::fmt::Debug, tracing::field::debug)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! _retry_logging {
    ($error_trait:path, $error_fmt:expr) => {{
        use $crate::Event;
        fn handle(
            event: &Event<
                impl $error_trait + std::fmt::Debug,
                impl $error_trait + std::fmt::Debug,
            >,
        ) {
            match event {
                Event::Retrying {
                    error,
                    num_attempts,
                    last_attempt_duration,
                    elapsed,
                    backoff,
                    overall_timeout,
                    max_attempts,
                    tags,
                    description,
                } => tracing::warn!(
                    error = $error_fmt(error),
                    attempt = %num_attempts,
                    ?last_attempt_duration,
                    ?elapsed,
                    ?backoff,
                    ?overall_timeout,
                    max_attempts,
                    ?tags,
                    "failed attempt at {description}. will retry after backoff",
                ),

                Event::Failed {
                    error,
                    num_attempts,
                    elapsed,
                    last_attempt_duration,
                    tags,
                    description,
                } => tracing::warn!(
                    error = $error_fmt(error),
                    %num_attempts,
                    ?elapsed,
                    ?last_attempt_duration,
                    ?tags,
                    "failed {description}. giving up",
                ),

                Event::Succeeded {
                    num_attempts,
                    elapsed,
                    last_attempt_duration,
                    tags,
                    description,
                } => tracing::debug!(
                    %num_attempts,
                    ?elapsed,
                    ?last_attempt_duration,
                    ?tags,
                    "finished {description}",
                ),
            }
        }
        handle
    }};
}
