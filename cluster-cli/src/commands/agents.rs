use anyhow::Context;
use cli_table::{format::Separator, print_stdout, Cell, CellStruct, Table};
use futures::future::join_all;
use reqwest::Url;

use hsmcore::hsm::types::HsmId;
use loam_mvp::http_client::Client;
use loam_mvp::realm::agent::types::{AgentService, StatusRequest, StatusResponse};
use loam_mvp::realm::store::bigtable::StoreClient;
use loam_sdk_networking::rpc::{self, RpcError};

pub async fn list_agents(c: &Client<AgentService>, store: &StoreClient) -> anyhow::Result<()> {
    let mut addresses: Vec<(HsmId, Url)> = store
        .get_addresses()
        .await
        .context("failed to get agent addresses from Bigtable")?;
    addresses.sort_by(|(_, url1), (_, url2)| url1.cmp(url2));

    let status_responses: Vec<Result<StatusResponse, RpcError>> = join_all(
        addresses
            .iter()
            .map(|(_hsm_id, url)| rpc::send(c, url, StatusRequest {})),
    )
    .await;

    let rows = addresses
        .into_iter()
        .zip(status_responses)
        .map(|((hsm_id, url), status)| format_row(hsm_id, url, status))
        .collect::<Vec<_>>();

    let table = rows
        .table()
        .separator(Separator::builder().title(Some(Default::default())).build())
        .title(vec!["Agent URL", "HSM ID", "Realm", "Groups"])
        .color_choice(cli_table::ColorChoice::Never);
    assert!(print_stdout(table).is_ok());
    println!();
    Ok(())
}

fn format_row(
    hsm_id: HsmId,
    url: Url,
    status: Result<StatusResponse, RpcError>,
) -> Vec<CellStruct> {
    [url.cell(), hsm_id.cell()]
        .into_iter()
        .chain(match status {
            Ok(StatusResponse { hsm }) => match hsm {
                Some(status) if status.id == hsm_id => match status.realm {
                    Some(realm_status) => {
                        let mut groups = realm_status
                            .groups
                            .iter()
                            .map(|group| format!("{:?} ({})", group.id, group.role))
                            .collect::<Vec<_>>();
                        groups.sort_unstable();
                        [
                            format!("{:?}", realm_status.id).cell(),
                            groups.join("\n").cell(),
                        ]
                    }
                    None => ["[no realm]".cell(), "".cell()],
                },
                Some(status) => [
                    format!("[unexpected HSM: found {}]", status.id).cell(),
                    "".cell(),
                ],
                None => ["[no HSM]".cell(), "".cell()],
            },
            Err(e) => [format!("[{e}]").cell(), "".cell()],
        })
        .collect::<Vec<_>>()
}
