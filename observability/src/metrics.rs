use dogstatsd::{DogstatsdResult, ServiceCheckOptions};
use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

/// Returns a stringified metrics [`Tag`] with a key and corresponding value.
///
/// Examples:
///
/// ```ignore
/// use crate::metrics_tag as tag;
/// tag!(?debugged);
/// tag!(displayed);
/// tag!(format: "for{}ted", "mat");
/// tag!("format": "literal");
/// ```
#[macro_export]
macro_rules! metrics_tag {
    ($k:ident) => {{
        $crate::metrics::Tag::from(format!("{}:{}", stringify!($k), $k))
    }};
    (?$k:ident) => {{
        $crate::metrics::Tag::from(format!("{}:{:?}", stringify!($k), $k))
    }};
    ($k:ident : $($arg:tt)*) => {{
        $crate::metrics::Tag::from(format!("{}:{}", stringify!($k), format_args!($($arg)*)))
    }};
    ($k:tt : $($arg:tt)*) => {{
        $crate::metrics::Tag::from(format!("{}:{}", $k, format_args!($($arg)*)))
    }};
}

#[derive(Debug)]
pub struct Tag(String);

impl From<String> for Tag {
    fn from(s: String) -> Self {
        Self(make_valid_tag(s))
    }
}

impl AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Helps with specifying generic types when you have no tags to pass.
pub const NO_TAGS: &[Tag] = &[];

/// Sends metrics over the network so they can be recorded.
///
/// This provides some conveniences around [`dogstatsd::Client`]:
/// - It is optional, so it can be excluded from tests.
/// - It is cheap to clone, so it can be given to async code.
/// - It warns on errors instead of returning them to the caller.
/// - It uses some more specific and convenient parameter types.
/// - It sends durations with nanosecond rather than millisecond precision.
///   (They are sent through the `statsd` protocol as distribution.)
#[derive(Clone, Debug)]
pub struct Client {
    inner: Option<Arc<dogstatsd::Client>>,
}

impl Client {
    /// Does not record metrics.
    pub const NONE: Self = Self { inner: None };

    pub fn new(service_name: &str) -> Self {
        Self::new_with_tags(service_name, [])
    }

    pub fn new_with_tags<I>(service_name: &str, tags: I) -> Self
    where
        I: IntoIterator<Item = Tag>,
    {
        let mut options = dogstatsd::OptionsBuilder::new();
        options.default_tag(metrics_tag!(service: "{service_name}").0);
        for tag in tags {
            options.default_tag(tag.0);
        }
        let client = dogstatsd::Client::new(options.build()).unwrap();
        Self {
            inner: Some(Arc::new(client)),
        }
    }

    /// See [`dogstatsd::Client::incr`].
    pub fn incr<'a, I, S, T>(&self, stat: S, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client.incr(metric_name(stat), tags).warn_err();
        }
    }

    /// See [`dogstatsd::Client::decr`].
    pub fn decr<'a, I, S, T>(&self, stat: S, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client.decr(metric_name(stat), tags).warn_err();
        }
    }

    /// See [`dogstatsd::Client::count`].
    pub fn count<'a, I, S, T>(&self, stat: S, count: i64, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client.count(metric_name(stat), count, tags).warn_err();
        }
    }

    /// See [`dogstatsd::Client::time`]. This version sends the elapsed
    /// time as a distribution with nanosecond precision.
    pub fn time<'a, F, O, I, S, T>(&self, stat: S, tags: I, block: F) -> O
    where
        F: FnOnce() -> O,
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if self.inner.is_some() {
            let start = Instant::now();
            let output = block();
            self.timing(stat, start.elapsed(), tags);
            output
        } else {
            block()
        }
    }

    /// See [`dogstatsd::Client::async_time`]. This version sends the elapsed
    /// time as a distribution with nanosecond precision.
    pub async fn async_time<'a, Fn, Fut, O, I, S, T>(&self, stat: S, tags: I, block: Fn) -> O
    where
        Fn: FnOnce() -> Fut,
        Fut: Future<Output = O>,
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if self.inner.is_some() {
            let start = Instant::now();
            let output = block().await;
            self.timing(stat, start.elapsed(), tags);
            output
        } else {
            block().await
        }
    }

    /// See [`dogstatsd::Client::timing`]. This version sends the duration as a
    /// distribution with nanosecond precision.
    pub fn timing<'a, I, S, T>(&self, stat: S, duration: Duration, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if self.inner.is_some() {
            self.distribution(
                metric_name(format!("{}.ns", stat.into())),
                duration.as_nanos().to_string(),
                tags,
            );
        }
    }

    /// See [`dogstatsd::Client::gauge`].
    pub fn gauge<'a, I, S, SS, T>(&self, stat: S, val: SS, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        SS: Value<'a>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client
                .gauge(metric_name(stat), val.into_cow(), tags)
                .warn_err();
        }
    }

    /// See [`dogstatsd::Client::distribution`].
    ///
    /// Note that histogram is explicitly not exposed as distribution is more useful.
    pub fn distribution<'a, I, S, SS, T>(&self, stat: S, val: SS, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        SS: Value<'a>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client
                .distribution(metric_name(stat), val.into_cow(), tags)
                .warn_err();
        }
    }

    /// See [`dogstatsd::Client::set`].
    pub fn set<'a, I, S, SS, T>(&self, stat: S, val: SS, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        SS: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client.set(metric_name(stat), val, tags).warn_err();
        }
    }

    /// See [`dogstatsd::Client::service_check`].
    pub fn service_check<'a, I, S, T>(
        &self,
        stat: S,
        val: dogstatsd::ServiceStatus,
        tags: I,
        options: Option<dogstatsd::ServiceCheckOptions>,
    ) where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            let mut msg = None;
            let mut hostname = None;
            let mut timestamp = None;
            if let Some(o) = &options {
                if let Some(m) = o.message {
                    msg = Some(make_valid_message(m));
                }
                if let Some(h) = o.hostname {
                    hostname = Some(make_valid_message(h));
                }
                timestamp = o.timestamp;
            }
            let fixed_options = Some(ServiceCheckOptions {
                timestamp,
                hostname: hostname.as_deref(),
                message: msg.as_deref(),
            });
            client
                .service_check(metric_name(stat), val, tags, fixed_options)
                .warn_err();
        }
    }

    /// See [`dogstatsd::Client::event`].
    pub fn event<'a, I, S, SS, T>(&self, title: S, text: SS, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        SS: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client.event(title, text, tags).warn_err();
        }
    }
}

fn metric_name<'a>(name: impl Into<Cow<'a, str>>) -> Cow<'a, str> {
    let n = name.into();
    debug_assert!(is_valid_metric_name(&n), "metric name '{n}' is invalid");
    n
}

// https://docs.datadoghq.com/developers/guide/what-best-practices-are-recommended-for-naming-metrics-and-tags/
// Metric names must start with a letter.
// Can only contain ASCII alphanumerics, underscores, and periods. Other characters are converted to underscores.
// Should not exceed 200 characters (though less than 100 is generally preferred from a UI perspective)
// Unicode is not supported.
// It is recommended to avoid spaces.
fn is_valid_metric_name(n: &str) -> bool {
    let mut bytes = n.bytes();
    match bytes.next() {
        None => return false,
        Some(c) if !c.is_ascii_alphabetic() => return false,
        Some(_) => {}
    }
    for c in bytes {
        if !matches!(c, b'a'..=b'z' | b'.' | b'_' | b'0'..=b'9' | b'A'..=b'Z') {
            return false;
        }
    }
    n.len() < 100
}

/// The Message field of service check should be serialized at the end of the
/// string but currently is not. This leads to issues where characters in the
/// message can break the parsing of the remaining payload, such as the tags.
/// This function will replace characters that are not valid in a message with a
/// '_'.
pub fn make_valid_message(m: &str) -> String {
    m.chars()
        .map(|c| {
            if matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// https://docs.datadoghq.com/developers/guide/what-best-practices-are-recommended-for-naming-metrics-and-tags/
// Returns the supplied tag with any uppercase characters converted to lowercase
// and any invalid characters replaced with _.
pub fn make_valid_tag(tag: String) -> String {
    let mut chars = tag.char_indices();
    let first_invalid: Option<(usize, char)> = match chars.next() {
        None => return String::from("empty_tag"),
        Some((_idx, 'a'..='z')) => chars.find(|(_, c)| !is_valid_tag_char(*c)),
        Some((idx, c)) => Some((idx, c)),
    };
    match first_invalid {
        None => tag,
        Some((idx, c)) => {
            let mut dest = String::with_capacity(tag.len() + 1);
            if idx == 0 && !c.is_ascii_uppercase() {
                dest.push_str("Z")
            } else {
                dest.push_str(&tag[..idx]);
            }
            dest.push(make_valid_tag_char(c));
            for (_, c) in chars {
                dest.push(make_valid_tag_char(c));
            }
            dest
        }
    }
}

fn is_valid_tag_char(c: char) -> bool {
    matches!(c, 'a'..='z' | '0'..='9' | '_' | '-' | ':' | '.' | '/')
}

fn make_valid_tag_char(c: char) -> char {
    match c {
        c if is_valid_tag_char(c) => c,
        'A'..='Z' => c.to_ascii_lowercase(),
        _ => '_',
    }
}

/// This trait allows numeric metric values to be recorded more ergonomically.
pub trait Value<'a> {
    fn into_cow(self) -> Cow<'a, str>;
}

impl<'a> Value<'a> for i32 {
    fn into_cow(self) -> Cow<'a, str> {
        self.to_string().into()
    }
}

impl<'a> Value<'a> for i64 {
    fn into_cow(self) -> Cow<'a, str> {
        self.to_string().into()
    }
}

impl<'a> Value<'a> for u32 {
    fn into_cow(self) -> Cow<'a, str> {
        self.to_string().into()
    }
}

impl<'a> Value<'a> for u64 {
    fn into_cow(self) -> Cow<'a, str> {
        self.to_string().into()
    }
}

impl<'a> Value<'a> for f32 {
    fn into_cow(self) -> Cow<'a, str> {
        self.to_string().into()
    }
}

impl<'a> Value<'a> for f64 {
    fn into_cow(self) -> Cow<'a, str> {
        self.to_string().into()
    }
}

impl<'a> Value<'a> for usize {
    fn into_cow(self) -> Cow<'a, str> {
        self.to_string().into()
    }
}

impl<'a> Value<'a> for Cow<'a, str> {
    fn into_cow(self) -> Cow<'a, str> {
        self
    }
}

impl<'a> Value<'a> for &'a str {
    fn into_cow(self) -> Cow<'a, str> {
        Cow::Borrowed(self)
    }
}

impl<'a> Value<'a> for String {
    fn into_cow(self) -> Cow<'a, str> {
        Cow::Owned(self)
    }
}

trait Warn {
    fn warn_err(&self);
}

impl Warn for DogstatsdResult {
    fn warn_err(&self) {
        if let Err(err) = self {
            warn!(?err, "failed to send metrics to Datadog agent");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::metrics::{is_valid_metric_name, make_valid_message, make_valid_tag};
    use crate::metrics_tag as tag;

    #[derive(Debug)]
    struct Debuggable;

    #[test]
    fn test_tag() {
        let debug = Debuggable;
        assert_eq!(tag!(?debug).0, "debug:debuggable");

        let display = "Displayable";
        assert_eq!(tag!(display).0, "display:displayable");

        assert_eq!(tag!(format: "Literal").0, "format:literal");

        assert_eq!(tag!(format: "for{}ted", "mat").0, "format:formatted");

        assert_eq!(tag!("format": "literal").0, "format:literal");

        assert_eq!(tag!("format": "For{}ted", "mat").0, "format:formatted");
    }

    #[test]
    fn test_valid_name() {
        assert!(is_valid_metric_name("b"));
        assert!(is_valid_metric_name("bob"));
        assert!(is_valid_metric_name("BoB"));
        assert!(is_valid_metric_name("B1"));
        assert!(is_valid_metric_name("B.0"));
        assert!(is_valid_metric_name("B_b"));
        assert!(is_valid_metric_name("app.request_time.ns"));
        assert!(is_valid_metric_name("bobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbob"));
        assert!(!is_valid_metric_name(""));
        assert!(!is_valid_metric_name("."));
        assert!(!is_valid_metric_name("9"));
        assert!(!is_valid_metric_name("99"));
        assert!(!is_valid_metric_name("_hello"));
        assert!(!is_valid_metric_name("::hello"));
        assert!(!is_valid_metric_name("app::hello"));
        assert!(!is_valid_metric_name("num bobs"));
        assert!(!is_valid_metric_name("num.bobs.🦀"));
        assert!(!is_valid_metric_name("bobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobAbobbobbobA"));
    }

    #[test]
    fn test_make_valid_message() {
        assert_eq!("bobbins", &make_valid_message("bobbins"));
        assert_eq!("hello_world", &make_valid_message("hello_world"));
        assert_eq!("hello_world", &make_valid_message("hello\nworld"));
        assert_eq!("hello_world", &make_valid_message("hello!world"));
        assert_eq!(
            "hello from  127.0.0.1_8080",
            &make_valid_message("hello from  127.0.0.1:8080")
        );
    }

    #[test]
    fn test_make_valid_tag() {
        let strs = [
            ("env:mmvp", "env:mmvp"),
            (
                "url:http://localhost:8080/foo",
                "url:http://localhost:8080/foo",
            ),
            ("name:Bob", "name:bob"),
            ("Name:BOB", "name:bob"),
            ("msg:help!", "msg:help_"),
            ("f:|#5000", "f:__5000"),
            ("", "empty_tag"),
            ("state:🦀y", "state:_y"),
            ("#size:10", "Z_size:10"),
            ("#:42", "Z_:42"),
            (":42", "Z:42"),
        ];
        for (input, exp) in strs {
            let actual = make_valid_tag(String::from(input));
            assert_eq!(exp, actual.as_str());
        }
    }
}
