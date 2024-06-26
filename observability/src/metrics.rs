use build_info::BuildInfo;
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
/// tag!(displayed);
/// tag!(?debugged);
/// tag!("name": displayed);
/// tag!("name": ?debugged);
/// tag!("name": format_args!("for{}ted", "mat"));
/// tag!(variable_containing_name: 3);
/// ```
#[macro_export]
macro_rules! metrics_tag {
    // displayed
    ($var:ident) => {{
        $crate::internal_metrics_tag_from_parts!(
            (format_args!("{}", stringify!($var))) : (format_args!("{}", $var))
        )
    }};
    // ?debugged
    (?$var:ident) => {{
        $crate::internal_metrics_tag_from_parts!(
            (format_args!("{}", stringify!($var))) : (format_args!("{:?}", $var))
        )
    }};
    // "name": displayed
    ($name:tt : $value:expr) => {{
        $crate::internal_metrics_tag_from_parts!(
            (format_args!("{}", $name)) : (format_args!("{}", $value))
        )
    }};
    // "name": ?debugged
    ($name:tt : ?$value:expr) => {{
        $crate::internal_metrics_tag_from_parts!(
            (format_args!("{}", $name)) : (format_args!("{:?}", $value))
        )
    }};
}

/// Helper for [`metrics_tag!`].
///
/// This would ideally be a normal function taking `fmt::Arguments`, but that
/// interacts poorly with async/async_trait.
///
/// `$name` and `$value` should be of type `fmt::Arguments`.
#[macro_export]
#[doc(hidden)]
macro_rules! internal_metrics_tag_from_parts {
    ($name:tt : $value:tt) => {{
        use ::std::borrow::Cow;
        let mut name_str = match $name.as_str() {
            Some(static_str) => Cow::Borrowed(static_str),
            None => Cow::Owned($name.to_string()),
        };
        if name_str.contains(':') {
            name_str = Cow::Owned(name_str.replace(':', "_"))
        }
        $crate::metrics::internal::make_valid_tag(format!("{}:{}", name_str, $value))
    }};
}

#[derive(Debug)]
pub struct Tag(String);

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

    pub fn new(service_name: &str, build: Option<&BuildInfo>) -> Self {
        Self::new_with_tags(service_name, build, [])
    }

    pub fn new_with_tags<I>(service_name: &str, build: Option<&BuildInfo>, tags: I) -> Self
    where
        I: IntoIterator<Item = Tag>,
    {
        let mut options = dogstatsd::OptionsBuilder::new();
        options.default_tag(metrics_tag!("service": service_name).0);
        for tag in tags {
            options.default_tag(tag.0);
        }
        if let Some(build) = build {
            if let Some(hash) = build.git_hash {
                options.default_tag(metrics_tag!("version": hash).0);
            }
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
                duration.as_nanos(),
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
                    msg = Some(make_valid_message(Cow::Borrowed(m)));
                }
                if let Some(h) = o.hostname {
                    hostname = Some(make_valid_message(Cow::Borrowed(h)));
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
            client
                .event(
                    make_valid_event_text(title.into()),
                    make_valid_event_text(text.into()),
                    tags,
                )
                .warn_err();
        }
    }
}

fn metric_name<'a>(name: impl Into<Cow<'a, str>>) -> Cow<'a, str> {
    let output = make_valid_metric_name(name.into());
    debug_assert!(
        output.len() < 100,
        "metric name '{output}' is longer than recommended"
    );
    output
}

// https://docs.datadoghq.com/developers/guide/what-best-practices-are-recommended-for-naming-metrics-and-tags/
// Metric names must start with a letter.
// Can only contain ASCII alphanumerics, underscores, and periods. Other characters are converted to underscores.
// Should not exceed 200 characters (though less than 100 is generally preferred from a UI perspective)
// Unicode is not supported.
// It is recommended to avoid spaces.
fn make_valid_metric_name(input: Cow<'_, str>) -> Cow<'_, str> {
    make_valid_string(
        input,
        "empty_metric",
        |c| c.is_ascii_alphabetic(),
        |c| matches!(c, b'a'..=b'z' | b'.' | b'_' | b'0'..=b'9' | b'A'..=b'Z'),
        |_c| b'_',
    )
}

/// The Message field of service check should be serialized at the end of the
/// string but currently is not. This leads to issues where characters in the
/// message can break the parsing of the remaining payload, such as the tags.
/// This function will replace characters that are not valid in a message with a
/// '_'.
fn make_valid_message(msg: Cow<'_, str>) -> Cow<'_, str> {
    fn valid(c: u8) -> bool {
        matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b' ')
    }
    make_valid_string(msg, "", valid, valid, |_c| b'_')
}

#[doc(hidden)]
pub mod internal {
    use super::{make_valid_string, Tag};
    use std::borrow::Cow;

    // https://docs.datadoghq.com/developers/guide/what-best-practices-are-recommended-for-naming-metrics-and-tags/
    // Returns the supplied tag with any uppercase characters converted to lowercase
    // and any invalid characters replaced with _.
    pub fn make_valid_tag(tag: String) -> Tag {
        Tag(make_valid_string(
            Cow::Owned(tag),
            "empty_tag",
            |c| c.is_ascii_lowercase(),
            |c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b':' |b'.' | b'/'),
            |c| {
                if c.is_ascii_alphabetic() {
                    c.to_ascii_lowercase()
                } else {
                    b'_'
                }
            },
        )
        .into_owned())
    }
}

// Returns a version of the input that only contains the allowed characters by
// replacing them with a different character. If the input does not start with
// an alpha character one will be added to the start of the string. Does not
// support unicode.
fn make_valid_string<'a>(
    input: Cow<'a, str>,
    // If input is empty, this will be returned.
    empty_value: &'a str,
    // return true if the supplied char is valid for the first position in the string.
    first_char_valid_fn: fn(u8) -> bool,
    // return true if the supplied char is valid for any position after the first character.
    char_valid_fn: fn(u8) -> bool,
    // return the character that should replace the provided invalid character.
    replacement: fn(u8) -> u8,
) -> Cow<'a, str> {
    let mut bytes = input.bytes();
    let first_invalid = match bytes.next() {
        None => return Cow::Borrowed(empty_value),
        Some(c) if first_char_valid_fn(c) => bytes.position(|b| !char_valid_fn(b)).map(|p| p + 1),
        Some(_) => Some(0),
    };
    match first_invalid {
        None => input,
        Some(idx) => {
            let mut dest = input.into_owned().into_bytes();
            if idx == 0 {
                // first char must be alpha
                let r = replacement(dest[0]);
                if !r.is_ascii_alphabetic() {
                    dest.insert(0, b'z');
                    // leave idx at 0 so that the filler loop checks
                    // what was the first char but isn't any more.
                } else {
                    dest[idx] = r;
                }
            } else {
                dest[idx] = replacement(dest[idx]);
            }
            for c in &mut dest[idx + 1..] {
                if !char_valid_fn(*c) {
                    *c = replacement(*c);
                }
            }
            Cow::Owned(String::from_utf8(dest).unwrap())
        }
    }
}

fn make_valid_event_text(mut input: Cow<'_, str>) -> Cow<'_, str> {
    // need to escape newlines.
    if input.contains('\n') {
        let text = input.to_mut();
        Cow::Owned(text.replace('\n', "\\\\n"))
    } else {
        input
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

impl<'a> Value<'a> for i128 {
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

impl<'a> Value<'a> for u128 {
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
    use std::borrow::Cow;

    use super::{
        internal::make_valid_tag, make_valid_event_text, make_valid_message, make_valid_metric_name,
    };
    use crate::metrics_tag as tag;

    #[derive(Debug)]
    struct Debuggable;

    #[test]
    fn test_tag() {
        let display = "Displayable";
        let debug = Debuggable;
        struct Struct {
            display: &'static str,
            debug: Debuggable,
        }
        let nested = Struct {
            display: "Displayable",
            debug: Debuggable,
        };

        assert_eq!(tag!(display).0, "display:displayable");
        assert_eq!(tag!(?debug).0, "debug:debuggable");
        assert_eq!(tag!("name": display).0, "name:displayable");
        assert_eq!(tag!("name": nested.display).0, "name:displayable");
        assert_eq!(tag!("name": ?nested.debug).0, "name:debuggable");
        assert_eq!(tag!("name": "literal").0, "name:literal");
        assert_eq!(tag!("na:me": "lit:eral").0, "na_me:lit:eral");
        assert_eq!(tag!("na\nme": "lit\neral").0, "na_me:lit_eral");
        assert_eq!(
            tag!("name": format_args!("for{}ted", "mat")).0,
            "name:formatted"
        );
        assert_eq!(tag!(display: 3).0, "displayable:3");
        assert_eq!(tag!((format_args!("for{}ted", "mat")): 3).0, "formatted:3");
    }

    #[test]
    fn test_make_valid_metric_name() {
        let strs = [
            ("b", "b"),
            ("BoB", "BoB"),
            ("B.1", "B.1"),
            ("B_2", "B_2"),
            (".", "z."),
            ("_", "z_"),
            ("9", "z9"),
            ("app:hello", "app_hello"),
            ("store.write.ns", "store.write.ns"),
            ("store#", "store_"),
            ("store.p99", "store.p99"),
            ("#p99", "z_p99"),
            ("", "empty_metric"),
            ("STORE_P99.9", "STORE_P99.9"),
            ("S!Help", "S_Help"),
            ("num.bobs.🦀", "num.bobs.____"),
        ];
        for (input, expected) in strs {
            let actual = make_valid_metric_name(Cow::Borrowed(input));
            assert_eq!(expected, actual, "with input '{input}'")
        }
    }
    #[test]
    fn test_make_valid_message() {
        let strs = [
            ("", ""),
            ("bobbins", "bobbins"),
            ("hello_world", "hello_world"),
            ("hello\nworld", "hello_world"),
            ("Hello!world", "Hello_world"),
            ("hello from  127.0.0.1:8080", "hello from  127.0.0.1_8080"),
        ];
        for (input, expected) in strs {
            let actual = make_valid_message(Cow::Borrowed(input));
            assert_eq!(expected, actual, "with input '{input}");
        }
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
            ("state:🦀y", "state:____y"),
            ("#size:10", "z_size:10"),
            ("#:42", "z_:42"),
            (":42", "z:42"),
        ];
        for (input, exp) in strs {
            let actual = make_valid_tag(String::from(input));
            assert_eq!(exp, actual.0.as_str());
        }
    }

    #[test]
    fn test_event_test() {
        let strs = [("test", "test"), ("hello\nworld", r"hello\\nworld")];
        for (input, expected) in strs {
            let actual = make_valid_event_text(Cow::Borrowed(input));
            assert_eq!(expected, actual, "with input '{input}'");
        }
    }
}
