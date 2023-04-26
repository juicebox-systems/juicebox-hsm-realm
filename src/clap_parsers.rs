use std::{net::SocketAddr, num::ParseIntError, time::Duration};

pub fn parse_duration(arg: &str) -> Result<Duration, ParseIntError> {
    let ms = arg.parse()?;
    Ok(Duration::from_millis(ms))
}

pub fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}
