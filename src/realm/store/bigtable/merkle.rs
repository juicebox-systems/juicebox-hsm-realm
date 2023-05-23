use crate::autogen::google;

use async_trait::async_trait;
use google::bigtable::v2::row_range::{EndKey::EndKeyOpen, StartKey::StartKeyClosed};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter, MutateRowsRequest, Mutation,
    ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use std::collections::HashMap;
use std::fmt::Write;
use std::time::Instant;
use tracing::{instrument, trace, Span};

use super::{mutate_rows, read_rows, Instance, MutateRowsError, StoreClient};
use crate::metrics_tag as tag;
use crate::realm::merkle::agent::TreeStoreReader;
use hsmcore::hsm::types::{DataHash, GroupId, RecordId};
use hsmcore::merkle::agent::{all_store_key_starts, Node, NodeKey, StoreKey, TreeStoreError};
use loam_sdk_core::marshalling;
use loam_sdk_core::types::RealmId;

fn merkle_table(instance: &Instance, realm: &RealmId) -> String {
    let mut buf = String::new();
    write!(
        buf,
        "projects/{project}/instances/{instance}/tables/",
        project = instance.project,
        instance = instance.instance
    )
    .unwrap();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-merkle").unwrap();
    buf
}

pub fn merkle_table_brief(realm: &RealmId) -> String {
    let mut buf = String::new();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-merkle").unwrap();
    buf
}

impl StoreClient {
    pub(super) async fn write_merkle_nodes(
        &self,
        realm: &RealmId,
        group: &GroupId,
        add: hashbrown::HashMap<NodeKey<DataHash>, Node<DataHash>>,
    ) -> Result<(), MutateRowsError> {
        if add.is_empty() {
            return Ok(());
        }

        let start = Instant::now();

        let new_merkle_entries = add
            .iter()
            .map(|(key, value)| mutate_rows_request::Entry {
                row_key: key.store_key().into_bytes(),
                mutations: vec![Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: String::from("f"),
                        column_qualifier: b"n".to_vec(),
                        timestamp_micros: -1,
                        // TODO: unnecessarily wraps the leaf node values.
                        value: marshalling::to_vec(value).expect("TODO"),
                    })),
                }],
            })
            .collect::<Vec<_>>();

        let mut bigtable = self.bigtable.clone();
        mutate_rows(
            &mut bigtable,
            MutateRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                entries: new_merkle_entries,
            },
        )
        .await?;

        self.metrics.timing(
            "store_client.write_merkle_nodes.time",
            start.elapsed(),
            [tag!(?realm), tag!(?group)],
        );
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    pub(super) async fn remove_merkle_nodes(
        &self,
        realm: &RealmId,
        group: &GroupId,
        remove: hashbrown::HashSet<NodeKey<DataHash>>,
    ) -> Result<(), MutateRowsError> {
        let start = Instant::now();

        let mut bigtable = self.bigtable.clone();
        let result = mutate_rows(
            &mut bigtable,
            MutateRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                entries: remove
                    .iter()
                    .map(|k| mutate_rows_request::Entry {
                        row_key: k.store_key().into_bytes(),
                        mutations: vec![Mutation {
                            mutation: Some(mutation::Mutation::DeleteFromRow(
                                mutation::DeleteFromRow {},
                            )),
                        }],
                    })
                    .collect(),
            },
        )
        .await;

        self.metrics.timing(
            "store_client.remove_merkle_nodes.time",
            start.elapsed(),
            [tag!(?realm), tag!(?group)],
        );
        result
    }
}

#[async_trait]
impl TreeStoreReader<DataHash> for StoreClient {
    #[instrument(level = "trace", skip(self), fields(num_result_nodes))]
    async fn path_lookup(
        &self,
        realm: &RealmId,
        record_id: &RecordId,
    ) -> Result<HashMap<DataHash, Node<DataHash>>, TreeStoreError> {
        let start = Instant::now();

        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: Vec::new(),
                    row_ranges: all_store_key_starts(record_id)
                        .into_iter()
                        .map(|prefix| RowRange {
                            end_key: Some(EndKeyOpen(prefix.next().into_bytes())),
                            start_key: Some(StartKeyClosed(prefix.into_bytes())),
                        })
                        .collect(),
                }),
                filter: Some(RowFilter {
                    filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        let nodes: HashMap<DataHash, Node<DataHash>> = rows
            .into_iter()
            .map(|(row_key, cells)| {
                let (_, hash) = StoreKey::parse(&row_key.0).unwrap();
                let node: Node<DataHash> = marshalling::from_slice(
                    &cells
                        .into_iter()
                        .find(|cell| cell.family == "f" && cell.qualifier == b"n")
                        .expect("every Merkle row should contain a node value")
                        .value,
                )
                .expect("TODO");
                (hash, node)
            })
            .collect();

        Span::current().record("num_result_nodes", nodes.len());
        self.metrics.timing(
            "store_client.path_lookup.time",
            start.elapsed(),
            [tag!(?realm)],
        );
        Ok(nodes)
    }

    #[instrument(level = "trace", skip(self))]
    async fn read_node(
        &self,
        realm: &RealmId,
        key: StoreKey,
    ) -> Result<Node<DataHash>, TreeStoreError> {
        trace!(realm = ?realm, key = ?key, "read_node starting");

        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: vec![key.clone().into_bytes()],
                    row_ranges: Vec::new(),
                }),
                filter: Some(RowFilter {
                    filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        let node = match rows.into_iter().next().and_then(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f" && cell.qualifier == b"n")
                .map(|cell| marshalling::from_slice(&cell.value).expect("TODO"))
                .expect("every Merkle row should contain a node value")
        }) {
            Some(node) => Ok(node),
            None => Err(TreeStoreError::MissingNode),
        };

        trace!(realm = ?realm, key = ?key, ok = node.is_ok(), "read_node completed");
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM1: RealmId = RealmId([
        0x66, 0x80, 0x13, 0x4b, 0xf4, 0x5d, 0xc9, 0x3f, 0xce, 0xee, 0xcd, 0x03, 0xe5, 0x38, 0xc8,
        0x9f,
    ]);

    #[test]
    fn test_merkle_table() {
        let instance = Instance {
            project: String::from("prj1"),
            instance: String::from("inst2"),
        };
        let expected =
            "projects/prj1/instances/inst2/tables/6680134bf45dc93fceeecd03e538c89f-merkle";
        assert_eq!(merkle_table(&instance, &REALM1), expected);
        assert_eq!(
            format!("{}/tables/{}", instance.path(), merkle_table_brief(&REALM1)),
            expected
        );
    }
}
