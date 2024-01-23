//! A feature-rich retry loop.
//!
//! No more ad hoc retry loops! Although a retry loop can be implemented
//! trivially with `loop { ... }`, such ad hoc loops tend to create maintenance
//! debt. The repeating pattern has been that, as we gain operational
//! experience, we want the loops to have better observability, better limits,
//! apply backoff, etc. These features are tedious to apply universally and
//! consistently, so this module implements our retry loop best practices in a
//! single place.
//!
//!  The [`Retry`] loop supports:
//! - logging,
//! - metrics with uniform naming,
//! - limiting the number of attempts,
//! - setting timeouts/deadlines that interrupt the work (by dropping the
//!   `Future`), and
//! - applying backoff (truncated exponential).
use std::error::Error;
use std::fmt::{self, Debug, Display};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout_at};
use tracing::{instrument, Span};

use crate::metrics;
use crate::metrics_tag;

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
        use $crate::retry_loop::Event;
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

/// The retry loop works with both deadlines and timeouts.
///
/// The timeout is useful for configuration and log messages.
///
/// The deadline can be a more convenient and composable way to stop at the
/// right time when you've done some work and have more work to do.
///
/// Since there is no maximum [`std::time::Instant`], an infinite
/// deadline/timeout is encoded as `DeadlineOrTimeout::Timeout(Duration::MAX)`.
#[derive(Debug)]
pub enum DeadlineOrTimeout {
    Deadline(Instant),
    Timeout(Duration),
}

/// Information passed to an individual [`Retry`] attempt.
#[derive(Debug)]
pub struct Context {
    /// Counts from 1.
    pub attempt: usize,
    /// The time budget remaining for the retry loop. After approximately this
    /// time, the attempt future will be dropped.
    pub timeout: Duration,
}

/// Configuration for a feature-rich retry loop.
///
/// See the [module-level documentation](`crate::retry_loop`).
#[derive(Debug)]
pub struct Retry<'a> {
    /// If true, [`Self::retry`] will make a single complete attempt and return
    /// the result without any observability. This takes precedence over
    /// everything else.
    pub disabled: bool,

    // Observability
    // -------------
    /// An English description of what the retry loop is aiming to accomplish.
    ///
    /// This should complete the templates "failed {}", "failed attempt at {}",
    /// and "finished {}", like "taking out the trash".
    pub description: &'a str,
    pub metrics: &'a metrics::Client,
    pub metrics_path: Option<&'a str>,
    /// The tags are intended for metrics but are also used for OTLP traces.
    pub tags: &'a [metrics::Tag],

    // Limits
    // ------
    pub max_attempts: usize,
    /// This is a strict time budget that will interrupt an ongoing attempt by
    /// dropping its [`Future`].
    pub time_limit: DeadlineOrTimeout,

    // Backoff
    // -------
    /// Clamped `<= max_backoff`.
    pub initial_backoff: Duration,
    /// Clamped `>= 1.0`.
    pub backoff_multiplier: f64,
    pub max_backoff: Duration,
}

impl<'a> Retry<'a> {
    /// Returns a new `Retry`, configured to loop for a fairly long time.
    ///
    /// `description` should complete the templates "failed {}", "failed
    /// attempt at {}", and "finished {}", like "taking out the trash".
    pub fn new(description: &'a str) -> Self {
        Self {
            disabled: false,
            description,
            metrics: &metrics::Client::NONE,
            metrics_path: None,
            tags: metrics::NO_TAGS,
            max_attempts: 1000,
            time_limit: DeadlineOrTimeout::Timeout(Duration::from_secs(60 * 5)),
            backoff_multiplier: 2.0,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_secs(2),
        }
    }

    /// Configures the retry loop to run exactly one attempt, without a timeout
    /// and without observability.
    ///
    /// This is useful when you're calling something that takes a Retry loop
    /// configuration but you don't actually want it to retry at that level.
    pub fn disabled() -> Self {
        Self {
            disabled: true,
            ..Self::new("(N/A)")
        }
    }

    /// Sets up the retry loop to report metrics.
    ///
    /// It will report the following metrics with the given `tags`:
    /// - `{path}.time` (timing): the overall execution time, including a tag
    ///    "result" set to "ok", "exhausted", or "fatal".
    /// - `{path}.fatal_errors` (incr): counts each fatal error, including the
    ///   error's tags.
    /// - `{path}.retryable_errors` (incr): counts each retryable error,
    ///   including the error's tags. One invocation of the retry loop can
    ///   cause this to increment many times.
    /// - `{path}.exhausted_errors` (incr): counts the number of times the
    ///   retry loop runs out of budget (no time or attempts remaining).
    ///
    /// Overwrites any prior metrics settings.
    pub fn with_metrics(
        self,
        client: &'a metrics::Client,
        path: &'a str,
        tags: &'a [metrics::Tag],
    ) -> Self {
        Self {
            metrics: client,
            metrics_path: Some(path),
            tags,
            ..self
        }
    }

    /// Sets the retry loop to time out (even interrupting an ongoing attempt).
    ///
    /// Overwrites any prior timeout or deadline.
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self {
            time_limit: DeadlineOrTimeout::Timeout(timeout),
            ..self
        }
    }

    /// Sets the retry loop to time out at a particular time (even interrupting
    /// an ongoing attempt).
    ///
    /// Overwrites any prior timeout or deadline.
    pub fn with_deadline(self, deadline: Option<Instant>) -> Self {
        let time_limit = match deadline {
            Some(deadline) => DeadlineOrTimeout::Deadline(deadline),
            None => DeadlineOrTimeout::Timeout(Duration::MAX),
        };
        Self { time_limit, ..self }
    }

    /// Sets the retry loop to stop after this many attempts.
    ///
    /// Overwrites any prior max attempts setting.
    pub fn with_max_attempts(self, max_attempts: usize) -> Self {
        Self {
            max_attempts,
            ..self
        }
    }

    /// Sets how long to wait after a transient error.
    ///
    /// The backoff after a retryable failed attempt will be:
    ///
    /// ```text
    /// min(initial * pow(multiplier, i), max)
    /// ```
    ///
    /// `initial` is clamped `<= max`.
    /// `multiplier` is clamped `>= 1.0`.
    ///
    /// Overwrites any prior backoff settings.
    pub fn with_exponential_backoff(
        self,
        initial: Duration,
        multiplier: f64,
        max: Duration,
    ) -> Self {
        Self {
            backoff_multiplier: multiplier,
            initial_backoff: initial,
            max_backoff: max,
            ..self
        }
    }

    /// Configures the `Retry` loop with the given function.
    ///
    /// This is helpful to centralize configuration of a category of retry
    /// loops, while maintaining the builder pattern's "fluent" code style.
    pub fn with<F>(self, f: F) -> Self
    where
        F: FnOnce(Self) -> Self,
    {
        f(self)
    }

    /// Run a retry loop.
    ///
    /// `try_once` should be an async function that does one attempt at the
    /// thing.
    ///
    /// `event_handler` should typically be [`crate::retry_logging!`] (or
    /// [`crate::retry_logging_debug!`] if the error types don't support
    /// [`std::fmt::Display`]).
    #[instrument(
        level = "trace",
        skip(self, try_once, event_handler),
        fields(
            description = self.description,
            tags = ?self.tags,
            num_attempts,
            last_attempt_duration,
            success,
        )
    )]
    pub async fn retry<F, FE, H, O, RE, T>(
        &mut self,
        mut try_once: F,
        mut event_handler: H,
    ) -> Result<T, RetryError<FE, RE>>
    where
        F: FnMut(Context) -> O,
        FE: Debug,
        H: FnMut(&Event<FE, RE>),
        O: Future<Output = Result<T, AttemptError<FE, RE>>>,
        RE: Debug,
    {
        if self.disabled {
            // Don't do any observability.
            return try_once(Context {
                attempt: 1,
                timeout: Duration::MAX,
            })
            .await
            .map_err(|error| match error {
                AttemptError::Fatal { error, .. } => RetryError::Fatal { error },
                AttemptError::Retryable { error, .. } => {
                    RetryError::Exhausted { last: Some(error) }
                }
            });
        }

        let start = Instant::now();
        let (deadline, overall_timeout) = match self.time_limit {
            DeadlineOrTimeout::Deadline(deadline) => {
                (Some(deadline), deadline.saturating_duration_since(start))
            }
            DeadlineOrTimeout::Timeout(timeout) => (start.checked_add(timeout), timeout),
        };

        let mut num_attempts = 0;
        let mut last_error: Option<RE> = None;
        let mut last_attempt_duration = Duration::ZERO;
        let mut elapsed = Duration::ZERO;

        // Tokio doesn't seem to short-circuit when timing out a function with
        // a past deadline, but the expected behavior is that if there's no
        // time budget going in, then no attempts should occur.
        let final_result = if self.max_attempts == 0 || overall_timeout == Duration::ZERO {
            Err(RetryError::Exhausted { last: None })
        } else {
            let mut next_backoff = Duration::min(self.initial_backoff, self.max_backoff);
            loop {
                num_attempts += 1;
                let attempt_start = Instant::now();
                let context = Context {
                    attempt: num_attempts,
                    timeout: match deadline {
                        Some(deadline) => deadline.saturating_duration_since(attempt_start),
                        None => Duration::MAX,
                    },
                };
                let attempt_result = match deadline {
                    Some(deadline) => timeout_at(deadline.into(), try_once(context)).await,
                    None => Ok(try_once(context).await),
                };
                let attempt_end = Instant::now();
                last_attempt_duration = attempt_end.saturating_duration_since(attempt_start);
                elapsed = attempt_end.saturating_duration_since(start);

                break match attempt_result {
                    Ok(Ok(r)) => {
                        event_handler(&Event::Succeeded {
                            num_attempts,
                            elapsed,
                            last_attempt_duration,
                            tags: self.tags,
                            description: self.description,
                        });
                        Ok(r)
                    }

                    Err(_ /* timed out */) => Err(RetryError::Exhausted { last: last_error }),

                    Ok(Err(AttemptError::Fatal {
                        error,
                        tags: error_tags,
                    })) => {
                        if let Some(metrics_path) = self.metrics_path {
                            self.metrics.incr(
                                format!("{}.fatal_errors", metrics_path),
                                self.tags.iter().chain(&error_tags),
                            );
                        }
                        Err(RetryError::Fatal { error })
                    }

                    Ok(Err(AttemptError::Retryable {
                        error,
                        tags: error_tags,
                    })) => {
                        if let Some(metrics_path) = self.metrics_path {
                            self.metrics.incr(
                                format!("{}.retryable_errors", metrics_path),
                                self.tags.iter().chain(&error_tags),
                            );
                        }

                        if num_attempts >= self.max_attempts
                            || deadline
                                .is_some_and(|deadline| deadline <= attempt_end + next_backoff)
                        {
                            Err(RetryError::Exhausted { last: Some(error) })
                        } else {
                            event_handler(&Event::Retrying {
                                error: &error,
                                num_attempts,
                                last_attempt_duration,
                                elapsed,
                                backoff: next_backoff,
                                overall_timeout,
                                max_attempts: self.max_attempts,
                                tags: self.tags,
                                description: self.description,
                            });
                            last_error = Some(error);
                            sleep(next_backoff).await;
                            next_backoff = next_backoff
                                .mul_f64(f64::max(1.0, self.backoff_multiplier))
                                .min(self.max_backoff);
                            continue;
                        }
                    }
                };
            }
        };

        if let Err(error) = &final_result {
            event_handler(&Event::Failed {
                error,
                num_attempts,
                elapsed,
                last_attempt_duration,
                tags: self.tags,
                description: self.description,
            });
        }

        if let Some(metrics_path) = self.metrics_path {
            if matches!(final_result, Err(RetryError::Exhausted { .. })) {
                self.metrics
                    .incr(format!("{}.exhausted_errors", metrics_path), self.tags);
            }

            let result_tag = match final_result {
                Ok(_) => "ok",
                Err(RetryError::Exhausted { .. }) => "exhausted",
                Err(RetryError::Fatal { .. }) => "fatal",
            };
            self.metrics.timing(
                format!("{}.time", metrics_path),
                elapsed,
                self.tags
                    .iter()
                    .chain([&metrics_tag!("result": result_tag)]),
            );
        }

        let span = Span::current();
        span.record(
            "last_attempt_duration",
            format!("{last_attempt_duration:?}"),
        );
        span.record("num_attempts", num_attempts);
        span.record("success", final_result.is_ok());

        return final_result;
    }
}

// Note: We don't have a good way to test metrics. These tests are written so
// that they report metrics, so you can verify manually that they look right.
//
// You can run a netcat server in the background, run test(s), and observe what
// happens. The following invocation through `strace` seems to be usable (on
// Linux with netcat-openbsd) to show distinct packets:
// ```
// strace -s 200 -e /read -v nc -l -p 8125 -u -k >/dev/null
// ```
//
// Alternatively, you can just run `tcpdump` and run test(s), but the output is
// uglier:
// ```
// sudo tcpdump -A -i lo 'udp port 8125'
// ```
#[cfg(test)]
mod tests {
    use super::*;
    use expect_test::expect;
    use std::sync::Mutex;

    struct TestLog(Mutex<Vec<String>>);

    impl TestLog {
        fn new() -> Self {
            Self(Mutex::new(Vec::new()))
        }

        fn handler(&self, event: &Event<'_, String, String>) {
            // serialization of deterministic fields in event
            let s = match event {
                Event::Retrying {
                    error,
                    num_attempts,
                    last_attempt_duration: _,
                    elapsed: _,
                    backoff,
                    overall_timeout,
                    max_attempts,
                    tags,
                    description,
                } => format!("Retrying {{ error: {error:?}, num_attempts: {num_attempts}, backoff: {backoff:?}, overall_timeout: {overall_timeout:?}, max_attempts: {max_attempts}, tags: {tags:?}, description: {description:?} }}"),
                Event::Failed {
                    error,
                    num_attempts,
                    elapsed: _,
                    last_attempt_duration: _,
                    tags,
                    description,
                } => format!("Failed {{ error: {error:?}, num_attempts: {num_attempts}, tags: {tags:?}, description: {description:?} }}"),
                Event::Succeeded {
                    num_attempts,
                    elapsed: _,
                    last_attempt_duration: _,
                    tags,
                    description,
                } => format!("Succeeded {{ num_attempts: {num_attempts}, tags: {tags:?}, description: {description:?} }}"),
            };
            self.0.lock().unwrap().push(s);
        }

        fn dump(self) -> String {
            let mut lines = self.0.into_inner().unwrap();
            lines.push(String::new());
            lines.join("\n")
        }
    }

    // Tests that `retry_logging!()` compiles with errors that impl Display.
    #[tokio::test]
    async fn test_retry_logging_display() {
        Retry::new("test")
            .retry(
                |_| async { Result::<(), AttemptError<String, String>>::Ok(()) },
                retry_logging!(),
            )
            .await
            .unwrap();
    }

    // Tests that `retry_logging_debug!()` compiles with errors that do/do not
    // impl Display.
    #[tokio::test]
    async fn test_retry_logging_debug() {
        Retry::new("test")
            .retry(
                |_| async { Result::<(), AttemptError<(), ()>>::Ok(()) },
                retry_logging_debug!(),
            )
            .await
            .unwrap();
        Retry::new("test")
            .retry(
                |_| async { Result::<(), AttemptError<String, String>>::Ok(()) },
                retry_logging_debug!(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_retry_disabled_ok() {
        let test_log = TestLog::new();
        let result = Retry::disabled()
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_disabled_ok",
                &[],
            )
            .retry(
                |context| async move {
                    Result::<_, AttemptError<String>>::Ok(format!("ok {}", context.attempt))
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(&result, Ok(msg) if msg == "ok 1"),
            "got {result:?}"
        );
        assert_eq!("", test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_disabled_retryable() {
        let test_log = TestLog::new();
        let result = Retry::disabled()
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_disabled_retryable",
                &[],
            )
            .retry(
                |context| async move {
                    Result::<(), AttemptError<_>>::Err(AttemptError::Retryable {
                        error: format!("retryable {}", context.attempt),
                        tags: vec![],
                    })
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(
                &result,
                Err(RetryError::Exhausted {
                    last: Some(error)
                }) if error == "retryable 1"
            ),
            "got {result:?}"
        );
        assert_eq!("", test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_disabled_fatal() {
        let test_log = TestLog::new();
        let result = Retry::disabled()
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_disabled_fatal",
                &[],
            )
            .retry(
                |context| async move {
                    Result::<(), AttemptError<_>>::Err(AttemptError::Fatal {
                        error: format!("fatal {}", context.attempt),
                        tags: vec![],
                    })
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(
                &result,
                Err(RetryError::Fatal { error }) if error == "fatal 1"
            ),
            "got {result:?}"
        );
        assert_eq!("", test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_success_right_away() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_success_right_away",
                &[],
            )
            .retry(
                |context| async move {
                    Result::<_, AttemptError<String>>::Ok(format!("ok {}", context.attempt))
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(&result, Ok(msg) if msg == "ok 1"),
            "got {result:?}"
        );
        expect![[r#"
            Succeeded { num_attempts: 1, tags: [], description: "testing" }
        "#]]
        .assert_eq(&test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_success_eventually() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_success_eventually",
                &[],
            )
            .with_exponential_backoff(Duration::from_nanos(8), 2.0, Duration::MAX)
            .retry(
                |context| async move {
                    if context.attempt == 3 {
                        Ok(format!("zebra {}", context.attempt))
                    } else {
                        Err(AttemptError::<String>::Retryable {
                            error: format!("not a zebra {}", context.attempt),
                            tags: vec![metrics_tag!("kind": "not_zebra")],
                        })
                    }
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(&result, Ok(msg) if msg == "zebra 3"),
            "got {result:?}"
        );
        expect![[r#"
            Retrying { error: "not a zebra 1", num_attempts: 1, backoff: 8ns, overall_timeout: 300s, max_attempts: 1000, tags: [], description: "testing" }
            Retrying { error: "not a zebra 2", num_attempts: 2, backoff: 16ns, overall_timeout: 300s, max_attempts: 1000, tags: [], description: "testing" }
            Succeeded { num_attempts: 3, tags: [], description: "testing" }
        "#]].assert_eq(&test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_fatal_right_away() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_fatal_right_away",
                &[],
            )
            .retry(
                |context| async move {
                    Result::<(), AttemptError<_>>::Err(AttemptError::Fatal {
                        error: format!("not a zebra {}", context.attempt),
                        tags: vec![metrics_tag!("kind": "not_zebra")],
                    })
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(
                &result,
                Err(RetryError::Fatal { error }) if error == "not a zebra 1"
            ),
            "got {result:?}"
        );
        expect![[r#"
            Failed { error: Fatal { error: "not a zebra 1" }, num_attempts: 1, tags: [], description: "testing" }
        "#]].assert_eq(&test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_fatal_eventually() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_fatal_eventually",
                &[],
            )
            .with_exponential_backoff(Duration::MAX, 0.1, Duration::from_nanos(3))
            .retry(
                |context| async move {
                    if context.attempt == 3 {
                        Result::<(), AttemptError<_>>::Err(AttemptError::Fatal {
                            error: format!("not a zebra {}", context.attempt),
                            tags: vec![metrics_tag!("kind": "not_zebra")],
                        })
                    } else {
                        Result::<(), AttemptError<_>>::Err(AttemptError::Retryable {
                            error: format!("retryable {}", context.attempt),
                            tags: vec![metrics_tag!("kind": "other")],
                        })
                    }
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(
                &result,
                Err(RetryError::Fatal { error }) if error == "not a zebra 3"
            ),
            "got {result:?}"
        );
        expect![[r#"
            Retrying { error: "retryable 1", num_attempts: 1, backoff: 3ns, overall_timeout: 300s, max_attempts: 1000, tags: [], description: "testing" }
            Retrying { error: "retryable 2", num_attempts: 2, backoff: 3ns, overall_timeout: 300s, max_attempts: 1000, tags: [], description: "testing" }
            Failed { error: Fatal { error: "not a zebra 3" }, num_attempts: 3, tags: [], description: "testing" }
        "#]].assert_eq(&test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_exhausted_attempts() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_exhausted_attempts",
                &[],
            )
            .with_exponential_backoff(Duration::ZERO, 1.0, Duration::ZERO)
            .with_max_attempts(2)
            .retry(
                |context| async move {
                    if context.attempt == 3 {
                        Ok(format!("zebra {}", context.attempt))
                    } else {
                        Err(AttemptError::<String>::Retryable {
                            error: format!("not a zebra {}", context.attempt),
                            tags: vec![metrics_tag!("kind": "not_zebra")],
                        })
                    }
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(
                &result,
                Err(RetryError::Exhausted {
                    last: Some(error)
                }) if error == "not a zebra 2",
            ),
            "{result:?}"
        );
        expect![[r#"
            Retrying { error: "not a zebra 1", num_attempts: 1, backoff: 0ns, overall_timeout: 300s, max_attempts: 2, tags: [], description: "testing" }
            Failed { error: Exhausted { last: Some("not a zebra 2") }, num_attempts: 2, tags: [], description: "testing" }
        "#]].assert_eq(&test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_exhausted_time() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_exhausted_time",
                &[],
            )
            .with_exponential_backoff(Duration::ZERO, 1.0, Duration::ZERO)
            .with_timeout(Duration::from_nanos(1))
            .retry(
                |context| async move {
                    // tokio's deadlines don't seem to be very strict, so
                    // setting this too small risks spurious failures.
                    sleep(Duration::from_millis(1000)).await;
                    Result::<(), AttemptError<String>>::Err(AttemptError::Fatal {
                        error: format!("not a zebra {}", context.attempt),
                        tags: vec![metrics_tag!("kind": "not_zebra")],
                    })
                },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(&result, Err(RetryError::Exhausted { last: None })),
            "{result:?}"
        );
        expect![[r#"
            Failed { error: Exhausted { last: None }, num_attempts: 1, tags: [], description: "testing" }
        "#]].assert_eq(&test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_no_attempts() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_no_attempts",
                &[],
            )
            .with_max_attempts(0)
            .retry(
                |_| async { Result::<_, AttemptError<String>>::Ok(3) },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(result, Err(RetryError::Exhausted { last: None })),
            "{result:?}"
        );
        expect![[r#"
            Failed { error: Exhausted { last: None }, num_attempts: 0, tags: [], description: "testing" }
        "#]].assert_eq(&test_log.dump());
    }

    #[tokio::test]
    async fn test_retry_no_time() {
        let test_log = TestLog::new();
        let result = Retry::new("testing")
            .with_metrics(
                &metrics::Client::new("retry_loop_unit_tests"),
                "test_retry_no_time",
                &[],
            )
            .with_deadline(Some(Instant::now()))
            .retry(
                |_| async { Result::<_, AttemptError<String>>::Ok(3) },
                |e| test_log.handler(e),
            )
            .await;
        assert!(
            matches!(result, Err(RetryError::Exhausted { last: None })),
            "{result:?}"
        );
        expect![[r#"
            Failed { error: Exhausted { last: None }, num_attempts: 0, tags: [], description: "testing" }
        "#]].assert_eq(&test_log.dump());
    }
}
