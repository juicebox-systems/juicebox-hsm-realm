use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Eq, PartialEq)]
pub enum ParseDurationError {
    Number,
    Unit,
}

impl Error for ParseDurationError {}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number => "error parsing number in duration",
            Self::Unit => {
                "error parsing unit in duration (valid units are: ns, µs/us, ms, s, m/min, h/hr, d/day)"
            }
        }
        .fmt(f)
    }
}

/// Accepts input like "1ns" or "10.3 s".
pub fn parse_duration(input: &str) -> Result<Duration, ParseDurationError> {
    let (number, unit) = match input.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(unit_start) => input.split_at(unit_start),
        None => (input, ""),
    };
    let number = f64::from_str(number).map_err(|_| ParseDurationError::Number)?;
    let unit = unit.strip_prefix(' ').unwrap_or(unit);
    let ns = match unit {
        "ns" => number,
        "µs" | "us" => number * 1e3,
        "ms" => number * 1e6,
        "s" => number * 1e9,
        "m" | "min" => number * 1e9 * 60.0,
        "h" | "hr" => number * 1e9 * 60.0 * 60.0,
        "d" | "day" | "days" => number * 1e9 * 60.0 * 60.0 * 24.0,
        _ => return Err(ParseDurationError::Unit),
    };
    Ok(Duration::from_nanos(ns.round() as u64))
}

pub fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{parse_duration, ParseDurationError};

    #[test]
    fn test_parse_duration() {
        assert_eq!(Ok(Duration::from_secs(1)), parse_duration("1.00 s"));
        assert_eq!(Ok(Duration::from_millis(100)), parse_duration(".1 s"));
        assert_eq!(Ok(Duration::from_millis(1100)), parse_duration("1.1 s"));
        assert_eq!(Ok(Duration::from_nanos(2)), parse_duration("2ns"));
        assert_eq!(
            Ok(Duration::from_nanos(3456789)),
            parse_duration("3456.789 us")
        );
        assert_eq!(
            Ok(Duration::from_nanos(3456789)),
            parse_duration("3456.789 µs")
        );
        assert_eq!(Ok(Duration::from_secs(1)), parse_duration("1000 ms"));
        assert_eq!(Ok(Duration::from_secs(1)), parse_duration("1 s"));
        assert_eq!(Ok(Duration::from_secs(60)), parse_duration("1 m"));
        assert_eq!(Ok(Duration::from_secs(7200)), parse_duration("2 h"));
        assert_eq!(Ok(Duration::from_secs(86400)), parse_duration("1 d"));
    }

    #[test]
    fn test_parse_duration_errors() {
        use ParseDurationError::{Number, Unit};
        for (err, input) in [
            (Number, ""),
            (Number, " "),
            (Number, "  "),
            (Number, "1.1.1 s"),
            (Number, "-3"),
            (Number, " 3"),
            (Number, "NaN"),
            (Unit, "1 eon"),
            (Unit, "1e9s"),
            (Unit, "3 s "),
            (Unit, "3 "),
            (Unit, "3  "),
            (Unit, "10    s"),
            (Unit, "1000"),
        ] {
            assert_eq!(Err(err), parse_duration(input), "{:?}", input);
        }
    }

    #[test]
    fn test_duration_round_trip() {
        for d in [
            Duration::new(0, 0),
            Duration::new(0, 1),
            Duration::new(0, 333),
            Duration::new(0, 1000),
            Duration::new(0, 1000000),
            Duration::new(0, 100000000),
            Duration::new(1, 0),
            Duration::new(1, 1),
            Duration::new(1, 333),
            Duration::new(1, 1000),
            Duration::new(1, 1000000),
            Duration::new(1, 100000000),
            Duration::new(60 * 60 * 24, 100000000),
        ] {
            assert_eq!(Ok(d), parse_duration(&format!("{d:?}")), "{d:?}");
        }
    }
}
