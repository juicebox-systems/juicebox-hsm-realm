use futures::{Stream, StreamExt};
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{empty, once};
use tokio_util::either::Either;

use jburl::Url;
use store::{ServiceKind, StoreClient};

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub(crate) struct Urls(pub Vec<Url>);
impl Urls {
    pub fn excluding(&self, u: &Url) -> Urls {
        let res = self.0.iter().filter(|url| *url != u).cloned().collect();
        Urls(res)
    }
}

#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub(crate) struct DiscoveredServices {
    urls: HashMap<ServiceKind, Urls>,
}

impl DiscoveredServices {
    pub fn urls_of_kind(&self, k: ServiceKind) -> Urls {
        match self.urls.get(&k) {
            Some(urls) => urls.clone(),
            None => Urls(Vec::new()),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DiscoveryWatcher {
    rx: watch::Receiver<DiscoveredServices>,
}

impl DiscoveryWatcher {
    pub fn new(store: StoreClient) -> Self {
        let (tx, rx) = watch::channel(DiscoveredServices::default());
        tokio::spawn(async move {
            loop {
                if let Ok(discovered) = store.get_addresses(None).await {
                    let mut urls: HashMap<ServiceKind, Urls> = HashMap::new();
                    for (url, kind) in discovered {
                        urls.entry(kind).or_default().0.push(url);
                    }
                    let urls = DiscoveredServices { urls };
                    tx.send_if_modified(|current_urls| {
                        if current_urls == &urls {
                            false
                        } else {
                            current_urls.urls = urls.urls;
                            true
                        }
                    });
                    sleep(Duration::from_secs(1)).await;
                }
            }
        });
        DiscoveryWatcher { rx }
    }

    pub fn urls(&self, kind: ServiceKind) -> Urls {
        self.rx.borrow().urls_of_kind(kind)
    }

    /// Returns an async stream of sets of discovered urls of the requested
    /// kind. The current set is immediately available on the stream, and then
    /// new items will be available each time the set of Urls changes.
    pub fn stream(&self, k: ServiceKind) -> impl Stream<Item = Urls> {
        let s = WatchStream::new(self.rx.clone());
        let mut last: Option<Urls> = None;
        s.flat_map(move |urls| {
            let new_urls = urls.urls_of_kind(k);
            if last.as_ref().is_some_and(|last| last == &new_urls) {
                Either::Left(empty())
            } else {
                last = Some(new_urls.clone());
                Either::Right(once(new_urls))
            }
        })
    }

    pub fn subscribe(&self, k: ServiceKind) -> watch::Receiver<Urls> {
        let current = self.rx.borrow().urls_of_kind(k);
        let (tx, rx) = watch::channel(current);
        let mut s = self.stream(k);
        tokio::spawn(async move {
            while let Some(urls) = s.next().await {
                tx.send_replace(urls);
            }
        });
        rx
    }
}
