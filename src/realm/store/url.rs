use std::fmt;

use reqwest::Url;
use serde::de::{Deserializer, Unexpected, Visitor};
use serde::ser::Serializer;

pub fn serialize<S>(v: &Url, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(v.as_str())
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(UrlVisitor())
}

struct UrlVisitor();

impl<'de> Visitor<'de> for UrlVisitor {
    type Value = Url;

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match Url::parse(v) {
            Ok(url) => Ok(url),
            Err(_) => Err(E::invalid_value(Unexpected::Str(v), &self)),
        }
    }
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "unable to parse url")
    }
}
