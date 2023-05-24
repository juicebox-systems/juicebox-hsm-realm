use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc,
};

pub mod bigtable;
pub mod certs;
pub mod cluster_gen;
pub mod hsm_gen;
pub mod panic;

/// Used to sequentially assign network ports.
#[derive(Clone)]
pub struct PortIssuer(Arc<AtomicU16>);

impl PortIssuer {
    pub fn new(starting: u16) -> Self {
        Self(Arc::new(AtomicU16::new(starting)))
    }
    pub fn next(&self) -> u16 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

impl From<u16> for PortIssuer {
    fn from(value: u16) -> Self {
        PortIssuer::new(value)
    }
}
