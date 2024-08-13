# Running an HSM realm

This document contains details on creating and running a real HSM realm using
Entrust HSMs. Its recommended that you read both [`README.md`](./README.md) and
[`entrust_hsm/README.md`](./entrust_hsm/README.md) before this document.


## Hardware

* 3 or more [Entrust nShield Solo XC HSM's](https://www.entrust.com/products/hsm/nshield-solo). The base model is fine.
* A CodeSafe license for each HSM.
* A Pack of Entrust blank smart cards.
* x64 servers of your choice to host the HSM PCIe cards.
* x64 servers to run the load balancer and cluster manager services.
  Alternatively these services can be run in a virtualized environment that is
  located in the same facility as the HSM servers.

## Cluster Sizing

The realm should include at least 2 cluster manager instances and 2 load
balancer instances. Larger clusters may need more load balancers depending on
the particular specifications of the servers used and the number of HSMs in the
cluster.

Local testing can be done with a single HSM, test clusters should have a minimum
of 3 HSMs. Production clusters should have at least 5 HSMs, as once the key
ceremony has been performed additional HSMs can not be added to the realm. A 5
HSM cluster gives some runway to handle failures.

In our testing a 5 HSM cluster (with 3 replication groups) should be able to
perform approx 240 recover operations a second. This throughput drops off
slightly as the size of the merkle tree increases. We observed a 5% drop in
throughput going from a tree with 10M leaves to a tree with 500M leaves. If more
throughput is required, you will need more HSMs and replication groups in your
realm.

## GCP

The GCP services Bigtable, Secret Manager and Cloud Pub/Sub are used by the
realm services. Credentials to access these will be needed for all hosts
(regardless of role) in the cluster. Bigtable should be configured for a single
zone as multi-zone configurations change the semantics of write operations. If
you are concerned about uptime with only a single zone, then you should run
multiple independent realms with a N of M client configuration. e.g. 2 HSM
realms and 1 software realm with a 2 of 3 client configuration.

Ideally your HSM servers are located in a facility that is close to the GCP zone
you plan to use.

## HSM Initialization

For test clusters the `entrust_ops` tool that is part of this repo can be used
to initialize the NVRAM and create the Security World and relevant keys. The
[`entrust_hsm/README.md`](./entrust_hsm/README.md) has more information about
this process. Unless you've purchased the remote card readers, then physical
access to the HSMs will be required during this process in order to connect the
card reader and swap cards at the appropriate times.

For production clusters a more rigorous key ceremony should be performed before
the HSMs are installed in the servers. The key ceremony allows external parties
to verify that the realm is running the expected HSM software and that only that
version of the software has access to the keys. The
[`ceremony`](https://github.com/juicebox-systems/ceremony) repo contains details
of a possible key ceremony structure and process. The result of the ceremony
includes a set of files called a Security World, a set of initialized HSMs and
the signed software. The HSMs should then be installed in their production
servers, and the security world files copied to the relevant location (typically
/opt/nfast/kmdata/local) on each HSM host server.

## Running the Agent

On each HSM host (aka Agent) server the `entrust_agent` executable and the signed
software files will need to be deployed. At this point the agent should be
runnable, the logging will indicate that it successfully started the HSM or
report some error condition. (typically GCP permissions). See the
[`entrust_hsm/README.md`](./entrust_hsm/README.md) for an example.

## Load Balancers

The clients send their requests to the realm over HTTPS to the load balancer
instances. The load balancer will authenticate the requests JWT token and then
route it to the relevant agent. You'll need TLS keys and certificates to start
the load balancer service. In addition you'll an ingress service to route
traffic to the load balancer service instances.

The load balancers expects to find a secret in GCP Secret Manager called
`record-id-randomization` that contains a 32 byte key used to randomize the hash
used to generate a merkle tree record id from the tenant and user information in
the request. If you have the `gcloud` tools installed then this snippet can be
used to create the key.

```sh
python3 -c \
'import secrets, json; print(json.dumps({"data": secrets.token_hex(32), "encoding": "Hex", "algorithm": "Blake2sMac256"}), end="")' | \
    gcloud \
        --project <gcp-project> \
        secrets create \
        record-id-randomization \
        --data-file - \
        --labels kind=record_id_randomization_key
```

## Realm Initialization

Once the agent is successfully running on each HSM server the realm
initialization can be performed. The `cluster` tool is used to perform many
administrative tasks. The `cluster agents` command can be used to sanity check
that the agents are running and accessible.

First use `cluster new-realm <some-agent>` to crete a new realm. This will
assign the realm its IDs and create and persist the initial merkle tree.
 
Then use `cluster join-realm --realm <realmID> <agent1> <agent2> ..` to have
the other HSMs join the same realm.

The initial realm creation created a single replication group with a single
member. At this point new replication groups can be created (via
`cluster new-group`) and the groups given ownership of part of the key space (via
`cluster transfer`). The `cluster groups` command can give a detailed report of
each replication groups status.

You'll need to decide the exact number of replication groups, and the
distribution of their members. Differing sizes of clusters may use different
approaches. For a 5 HSM cluster we recommend 3 replication groups each
containing all 5 HSMs as members and each replication group owning a third of
the key space. In larger clusters its not required that all HSMs are members of
all replication groups.

## Services

The agent, load balancer and cluster manager services will all panic in
unexpected and unrecoverable error conditions. A process supervisor such as
Systemd should be used to manage these services and restart the process as
needed.

The services generate logs to `stdout` and publish metrics to Datadog if the
Datadog agent is installed.

The `service_checker` tool can be used to repeated make requests to a realm and
report errors via a Datadog service-check.

## Tenants

Requests to the realm authenticate using JWT. The JWT key(s) for a tenant are
store in Secret Manager. The `gcloud` tool can be useful in creating these, e.g.

```sh
python3 -c \
    'import secrets, json; print(json.dumps({"data": secrets.token_hex(32), "encoding": "Hex", "algorithm": "HmacSha256"}), end="")' | \
    gcloud \
        --project <gcp-project> \
        secrets create \
        "tenant-test-$TENANT" \
        --data-file - \
        --labels kind=tenant_auth_key
```

`RsaPkcs1Sha256` and `Edwards25519` algorithms are also supported and are better
choices for production tenants.

By default each tenant is rate limited to 10 requests a second. The `cluster
tenant` command can be used to set a different rate limit for a tenant.

## Tenant Event Log Service

The tenant event log service contained in the software realm repo is used for
both software realms and HSM realms. You will need to the tenant event log
service with it configured to use the same GCP zone/project as the HSM realm.
The ['tenant-log-client'](../tenant-log-client) repo contains a sample client
application as well as [documentation](../tenant-log-client/API.md) on the
exposed API.

## Client Configuration

The `cluster configuration` command can help with generating a basic
configuration for use by the client SDK. You will need to adjust this manually
for mixed HSM/software realm configurations. If your client integration is not
yet ready then the `service_checker` tool can be helpful in verifying everything
is working as expected.
