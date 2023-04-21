use clap::{command, Parser, Subcommand};
use cli_table::{
    format::{Justify, Separator},
    print_stdout, Cell, Table,
};
use futures::{future::join_all, FutureExt};
use reqwest::Url;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use hsmcore::hsm::types::{GroupId, HsmId, LogIndex};
use loam_mvp::{
    google_auth,
    http_client::{Client, ClientOptions},
    realm::{
        agent::types::{AgentService, StatusRequest},
        cluster::types::{ClusterService, StepdownAsLeaderRequest, StepdownAsLeaderResponse},
        store::bigtable::{BigTableArgs, StoreClient},
    },
};
use loam_sdk::RealmId;
use loam_sdk_networking::rpc::{self, RpcError};

#[derive(Parser)]
#[command(about = "A CLI tool for interacting with the Cluster")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// Url to the cluster manager.
    #[arg(short, long, default_value = "http://localhost:8079")]
    cluster: Url,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Ask the HSM to stepdown as leader for any groups that is leading.
    Stepdown { hsm: String },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let c = Client::<AgentService>::new(ClientOptions::default());
    let auth_manager = if args.bigtable.needs_auth() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store = args
        .bigtable
        .connect_data(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable");

    let result = match &args.command {
        Some(Commands::Stepdown { hsm }) => match resolve_hsm_id(&store, hsm).await {
            Err(e) => {
                println!("{}", e);
                return;
            }
            Ok(id) => stepdown(&args.cluster, id).await,
        },
        None => status(c, store).await,
    };
    if let Err(err) = result {
        println!("error: {:?}", err);
    }
}

async fn resolve_hsm_id(store: &StoreClient, id: &str) -> Result<HsmId, String> {
    if id.len() == 32 {
        let h = hex::decode(id).map_err(|e| format!("{e:?}"))?;
        Ok(HsmId(h.try_into().unwrap()))
    } else {
        let id = id.to_lowercase();
        let ids: Vec<_> = store
            .get_addresses()
            .await
            .map_err(|e| format!("RPC error to bigtable {e:?}"))?
            .into_iter()
            .filter(|(hsm_id, _url)| hsm_id.to_string().to_lowercase().starts_with(&id))
            .collect();
        match ids.len() {
            0 => Err(String::from("No HSM with that id.")),
            1 => Ok(ids[0].0),
            c => Err(format!(
                "Ambiguous Hsm id, there are {c} HSMs that start with that id."
            )),
        }
    }
}

async fn stepdown(cluster_url: &Url, hsm: HsmId) -> Result<(), RpcError> {
    let c = Client::<ClusterService>::new(ClientOptions::default());
    let r = rpc::send(&c, cluster_url, StepdownAsLeaderRequest::Hsm(hsm)).await;
    match r {
        Ok(StepdownAsLeaderResponse::Ok) => {
            println!("Leader stepdown successfully completed");
            Ok(())
        }
        Ok(s) => {
            println!("Leader stepdown had error {s:?}");
            Ok(())
        }
        Err(err) => {
            println!("Leader stepdown had rpc error: {err:?}");
            Err(err)
        }
    }
}

async fn status(c: Client<AgentService>, store: StoreClient) -> Result<(), RpcError> {
    println!("Status");
    let addresses = store.get_addresses().await.map_err(|_| RpcError::Network)?;
    println!("{} Agents listed in service discovery", addresses.len());

    let s: Vec<_> =
        join_all(addresses.iter().map(|(hsm_id, url)| {
            rpc::send(&c, url, StatusRequest {}).map(move |r| (r, hsm_id, url))
        }))
        .await
        .into_iter()
        .filter_map(|(s, hsm_id, _)| s.ok().and_then(|s| s.hsm).filter(|s| s.id == *hsm_id))
        .collect();

    #[derive(Default)]
    struct GroupInfo {
        members: Vec<(HsmId, Option<LogIndex>)>,   //captured
        leader: Option<(HsmId, Option<LogIndex>)>, //commit
    }
    let mut realms: BTreeMap<RealmId, BTreeSet<GroupId>> = BTreeMap::new();
    let mut groups: BTreeMap<GroupId, GroupInfo> = BTreeMap::new();
    for sr in s {
        if let Some(r) = sr.realm {
            for g in r.groups {
                realms.entry(r.id).or_default().insert(g.id);
                let e = groups.entry(g.id).or_default();
                e.members
                    .push((sr.id, g.captured.map(|(index, _hmac)| index)));
                if g.leader.is_some() {
                    e.leader = Some((sr.id, g.leader.unwrap().committed));
                }
            }
        }
    }

    let addresses: HashMap<HsmId, Url> = addresses.into_iter().collect();
    for (realm, realm_groups) in realms {
        println!("Realm: {:?}", realm);
        for group_id in realm_groups {
            println!("\tGroup: {:?}", group_id);
            let group = &groups[&group_id];
            let rows: Vec<_> = group
                .members
                .iter()
                .map(|(hsm_id, captured)| {
                    vec![
                        hsm_id.to_string().cell(),
                        addresses.get(hsm_id).unwrap().to_string().cell(),
                        match captured {
                            None => "None".cell(),
                            Some(i) => i.to_string().cell(),
                        }
                        .justify(Justify::Right),
                        match group.leader {
                            Some((leader_id, Some(commit_idx))) if leader_id == *hsm_id => {
                                commit_idx.to_string().cell()
                            }
                            Some((leader_id, None)) if leader_id == *hsm_id => "None".cell(),
                            None | Some(_) => "".cell(),
                        }
                        .justify(Justify::Right),
                    ]
                })
                .collect();
            let table = rows
                .table()
                .separator(Separator::builder().title(Some(Default::default())).build())
                .title(vec!["HSM", "Agent URL", "Captured", "Commit"])
                .color_choice(cli_table::ColorChoice::Never);
            assert!(print_stdout(table).is_ok());
        }
        println!();
    }
    Ok(())
}
