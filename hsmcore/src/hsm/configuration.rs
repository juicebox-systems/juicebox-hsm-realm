extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::slice;
use serde::{Deserialize, Serialize};

use super::{HsmId, CONFIGURATION_LIMIT};

/// A fixed set of HSMs forming a replication group.
///
/// A strict majority of the HSMs in the group is needed to form a quorum,
/// which is needed to commit a new log entry.
///
/// Invariants:
/// - Sorted by HSM ID.
/// - No duplicates.
/// - Must contain between 1 and [`CONFIGURATION_LIMIT`] HSMs, inclusive.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GroupConfiguration(Vec<HsmId>);

impl GroupConfiguration {
    pub fn from_local(local: &HsmId) -> Self {
        Self(vec![*local])
    }

    pub fn from_sorted_including_local(
        hsms: Vec<HsmId>,
        local: &HsmId,
    ) -> Result<Self, &'static str> {
        if hsms.is_empty() {
            // This is redundant with checking that `hsms` contains `local`,
            // but it's probably a more useful error message.
            return Err("configuration needs at least 1 HSM");
        }
        if hsms.len() > usize::from(CONFIGURATION_LIMIT) {
            return Err("too many HSMs in configuration");
        }

        let mut pairwise = hsms.iter().zip(hsms.iter().skip(1));
        if !pairwise.all(|(a, b)| a < b) {
            return Err("HSM IDs need to be sorted and unique in configuration");
        }

        // This could use `hsms.binary_search()`, but that's probably more
        // code bloat than execution time saved.
        if !hsms.contains(local) {
            return Err("configuration should include local HSM ID");
        }

        Ok(Self(hsms))
    }

    /// Returns a vector in sorted order.
    pub fn to_vec(&self) -> Vec<HsmId> {
        self.0.clone()
    }
}

/// Returns an iterator in sorted order.
impl<'a> IntoIterator for &'a GroupConfiguration {
    type Item = &'a HsmId;
    type IntoIter = slice::Iter<'a, HsmId>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_sorted_including_local() {
        GroupConfiguration::from_sorted_including_local(
            vec![HsmId([0x00; 16]), HsmId([0xff; 16])],
            &HsmId([0xff; 16]),
        )
        .unwrap();

        assert_eq!(
            GroupConfiguration::from_sorted_including_local(
                vec![HsmId([0xff; 16]), HsmId([0x00; 16])],
                &HsmId([0xff; 16]),
            )
            .unwrap_err(),
            "HSM IDs need to be sorted and unique in configuration"
        );

        assert_eq!(
            GroupConfiguration::from_sorted_including_local(
                vec![HsmId([0xff; 16]), HsmId([0xff; 16])],
                &HsmId([0xff; 16]),
            )
            .unwrap_err(),
            "HSM IDs need to be sorted and unique in configuration"
        );

        assert_eq!(
            GroupConfiguration::from_sorted_including_local(
                vec![HsmId([0x00; 16]), HsmId([0xff; 16])],
                &HsmId([0x88; 16]),
            )
            .unwrap_err(),
            "configuration should include local HSM ID"
        );
    }
}
