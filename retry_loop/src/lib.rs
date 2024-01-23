//! A feature-rich retry loop.
//!
//! No more ad hoc retry loops! Although a retry loop can be implemented
//! trivially with `loop { ... }`, such ad hoc loops tend to create maintenance
//! debt. The repeating pattern has been that, as we gain operational
//! experience, we want the loops to have better observability, better limits,
//! apply backoff, etc. These features are tedious to apply universally and
//! consistently, so this crate implements our retry loop best practices in a
//! single place.
//!
//!  The [`Retry`] loop supports:
//! - logging,
//! - metrics with uniform naming,
//! - limiting the number of attempts,
//! - setting timeouts/deadlines that interrupt the work (by dropping the
//!   `Future`), and
//! - applying backoff (truncated exponential).
use std::fmt::Debug;
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout_at};
use tracing::{instrument, Span};

use observability::{metrics, metrics_tag};

mod errors;
mod logging;
#[cfg(test)]
mod tests;

pub use errors::{AttemptError, NoFatalErrors, RetryError};
pub use logging::Event;

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
/// See the [crate-level documentation](`crate`).
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
