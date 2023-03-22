use std::{num::ParseIntError, time::Duration};

pub fn parse_duration(arg: &str) -> Result<Duration, ParseIntError> {
    let ms = arg.parse()?;
    Ok(Duration::from_millis(ms))
}
