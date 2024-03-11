use std::fmt::{self, Debug, Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use url::ParseError;

// The Debug output for url::Url is very verbose, this wraps it to use the same
// Display format for both Display & Debug.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Url(url::Url);

impl Url {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        url::Url::parse(s).map(Self)
    }

    pub fn join(&self, input: &str) -> Result<Self, ParseError> {
        self.0.join(input).map(Self)
    }
}

impl FromStr for Url {
    type Err = ParseError;

    #[inline]
    fn from_str(input: &str) -> Result<Url, Self::Err> {
        Url::parse(input)
    }
}

impl<'a> TryFrom<&'a str> for Url {
    type Error = ParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Url::parse(s)
    }
}

impl From<url::Url> for Url {
    fn from(value: url::Url) -> Self {
        Self(value)
    }
}

impl From<Url> for url::Url {
    fn from(value: Url) -> Self {
        value.0
    }
}

impl Deref for Url {
    type Target = url::Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Url {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use crate::Url;

    #[test]
    fn formatting() {
        let u = Url::parse("https://juicebox.xyz/path").unwrap();
        assert_eq!("https://juicebox.xyz/path", &format!("{u:?}"));
        assert_eq!("https://juicebox.xyz/path", &format!("{u}"));
    }

    #[test]
    fn deref() {
        let u = Url::parse("https://juicebox.xyz/path").unwrap();
        assert_eq!(Some("juicebox.xyz"), u.host_str());
    }
}
