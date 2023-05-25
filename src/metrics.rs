use dogstatsd::DogstatsdResult;
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
        Self(s)
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
///   (They are sent through the `statsd` protocol as histograms.)
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
            client.incr(stat, tags).warn_err();
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
            client.decr(stat, tags).warn_err();
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
            client.count(stat, count, tags).warn_err();
        }
    }

    /// See [`dogstatsd::Client::time`]. This version sends the elapsed
    /// time as a histogram with nanosecond precision.
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
    /// time as a histogram with nanosecond precision.
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
    /// histogram with nanosecond precision.
    pub fn timing<'a, I, S, T>(&self, stat: S, duration: Duration, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if self.inner.is_some() {
            self.histogram(
                format!("{}.ns", stat.into()),
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
            client.gauge(stat, val.into_cow(), tags).warn_err();
        }
    }

    /// See [`dogstatsd::Client::histogram`].
    pub fn histogram<'a, I, S, SS, T>(&self, stat: S, val: SS, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        SS: Value<'a>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client.histogram(stat, val.into_cow(), tags).warn_err();
        }
    }

    /// See [`dogstatsd::Client::distribution`].
    pub fn distribution<'a, I, S, SS, T>(&self, stat: S, val: SS, tags: I)
    where
        I: IntoIterator<Item = T>,
        S: Into<Cow<'a, str>>,
        SS: Into<Cow<'a, str>>,
        T: AsRef<str>,
    {
        if let Some(client) = &self.inner {
            client.distribution(stat, val, tags).warn_err();
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
            client.set(stat, val, tags).warn_err();
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
            client.service_check(stat, val, tags, options).warn_err();
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
mod test {
    use crate::metrics_tag as tag;

    #[derive(Debug)]
    struct Debuggable;

    #[test]
    fn test_tag() {
        let debug = Debuggable;
        assert_eq!(tag!(?debug).0, "debug:Debuggable");

        let display = "Displayable";
        assert_eq!(tag!(display).0, "display:Displayable");

        assert_eq!(tag!(format: "Literal").0, "format:Literal");

        assert_eq!(tag!(format: "For{}ted", "mat").0, "format:Formatted");

        assert_eq!(tag!("format": "Literal").0, "format:Literal");

        assert_eq!(tag!("format": "For{}ted", "mat").0, "format:Formatted");
    }
}