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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
            &metrics::Client::new("retry_loop_unit_tests", None),
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
