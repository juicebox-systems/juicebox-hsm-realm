use std::time::{Duration, Instant};
use tokio::time::sleep;

use observability::metrics;

pub async fn start_uptime_reporter(c: metrics::Client) {
    let start = Instant::now();
    tokio::spawn(async move {
        loop {
            c.timing("service.uptime", start.elapsed(), metrics::NO_TAGS);
            sleep(Duration::from_secs(1)).await;
        }
    });
}
