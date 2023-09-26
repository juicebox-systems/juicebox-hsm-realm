## `cluster --help`

```
A CLI tool for interacting with the cluster

Usage: cluster [OPTIONS] <COMMAND>

Commands:
  agents         Print detailed information about every discoverable agent
  auth-token     Create an auth token for a test tenant
  configuration  Print a configuration that uses the discoverable realm(s)
  experimental   Subcommands that are not yet stable and may be dangerous
  groups         Print information about every discoverable realm and group
  join-realm     Request HSMs to irreversibly adopt an existing realm
  new-group      Create a new group on a set of agents' HSMs
  new-realm      Create a new realm and group on a single agent's HSM
  stepdown       Ask an HSM to step down as leader
  transfer       Transfer ownership of user records from one group to another
  user-summary   Report counts of active users by tenant for a month. These are users that have a secret stored at some point during the month (in the UTC timezone)
  help           Print this message or the help of the given subcommand(s)

Options:
      --bigtable-project <PROJECT>    The name of the GCP project that contains the bigtable instance [default: prj]
      --bigtable-instance <INSTANCE>  The name of the bigtable instance to connect to [default: instance]
      --bigtable-url <URL>            The url to the big table emulator [default uses GCP endpoints]
  -h, --help                          Print help
  -V, --version                       Print version

```

## `cluster agents --help`

```
Print detailed information about every discoverable agent.

See 'groups' for a higher-level view of the realms and groups in the cluster.

Usage: cluster agents

Options:
  -h, --help
          Print help (see a summary with '-h')

```

## `cluster auth-token --help`

```
Create an auth token for a test tenant.

The token is printed to stdout.

Usage: cluster auth-token <TENANT> <USER> <REALM> [SCOPE]

Arguments:
  <TENANT>
          A tenant ID that must begin with "test-".
          
          The tenant's secret auth key must already exist in GCP Secret Manager.

  <USER>
          Any user ID

  <REALM>
          The ID of the realm that the token should be valid for

  [SCOPE]
          The scope(s) to include in the token
          
          [default: ]

Options:
  -h, --help
          Print help (see a summary with '-h')

```

## `cluster configuration --help`

```
Print a configuration that uses the discoverable realm(s).

The configuration is printed in a JSON format that the demo client accepts.

Usage: cluster configuration <LOAD_BALANCER>

Arguments:
  <LOAD_BALANCER>
          A URL to a load balancer that sends requests to all of the discoverable realms.
          
          The load balancer is not accessed, but its URL is included in the configuration.

Options:
  -h, --help
          Print help (see a summary with '-h')

```

## `cluster experimental --help`

```
Subcommands that are not yet stable and may be dangerous

Usage: cluster experimental <COMMAND>

Commands:
  assimilate  Reconfigure any available agents/HSMs into a nominal and well-balanced realm
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help

```

## `cluster experimental assimilate --help`

```
Reconfigure any available agents/HSMs into a nominal and well-balanced realm.

This is marked experimental because it does not currently handle all scenarios. It's included because it can still be a useful time-saving tool for development and testing purposes for scenarios it does support.

Usage: cluster experimental assimilate [OPTIONS]

Options:
      --group-size <GROUP_SIZE>
          The target number of HSMs per group (and also the number of groups each HSM is a member of).
          
          The number of HSMs available must be at least this large.
          
          [default: 5]

      --realm <REALM>
          If provided, the HSMs already in this realm, as well as HSMs not currently in any realm, are assimilated.
          
          Default: create a new realm if none are discoverable, use the one realm if exactly one is found, or fail if more than one realm is found.

  -h, --help
          Print help (see a summary with '-h')

```

## `cluster groups --help`

```
Print information about every discoverable realm and group.

This does not include information about agents that are not participating in any groups. See 'agents' for lower-level information about agents.

Usage: cluster groups

Options:
  -h, --help
          Print help (see a summary with '-h')

```

## `cluster join-realm --help`

```
Request HSMs to irreversibly adopt an existing realm.

At least one HSM that is already in the realm must be online for this to complete.

Usage: cluster join-realm --realm <REALM> <AGENTS>...

Arguments:
  <AGENTS>...
          URLs of agents whose HSMs will join the realm

Options:
      --realm <REALM>
          The ID of the realm to join

  -h, --help
          Print help (see a summary with '-h')

```

## `cluster new-group --help`

```
Create a new group on a set of agents' HSMs.

The new group will not have ownership of any user records. Use 'transfer' to assign it ownership.

Usage: cluster new-group --realm <REALM> <AGENTS>...

Arguments:
  <AGENTS>...
          URLs of agents whose HSMs will form the new group.
          
          All of the HSMs should have already joined the realm.

Options:
      --realm <REALM>
          The ID of the realm in which to create the new group

  -h, --help
          Print help (see a summary with '-h')

```

## `cluster new-realm --help`

```
Create a new realm and group on a single agent's HSM.

The new group will own all of the user record space. Use 'new-group' and 'transfer' to repartition across additional groups.

Usage: cluster new-realm <AGENT>

Arguments:
  <AGENT>
          URL of agent whose HSM will form the new realm and group

Options:
  -h, --help
          Print help (see a summary with '-h')

```

## `cluster stepdown --help`

```
Ask an HSM to step down as leader

Usage: cluster stepdown [OPTIONS] <ID>

Arguments:
  <ID>  A full or an unambiguous prefix of an HSM or Group ID

Options:
  -c, --cluster <CLUSTER>     URL to a cluster manager, which will execute the request. By default it will find a cluster manager using service discovery
      --type <STEPDOWN_TYPE>  Treat the supplied ID specifically as a HSM or group identifier. If not set will look for matches against known HSM and group ids and act accordingly [possible values: hsm, group]
  -h, --help                  Print help

```

## `cluster transfer --help`

```
Transfer ownership of user records from one group to another.

Both groups must already exist and be part of the same realm.

Usage: cluster transfer --realm <REALM> --source <SOURCE> --destination <DESTINATION> --start <START> --end <END>

Options:
      --realm <REALM>
          Realm ID

      --source <SOURCE>
          ID of group that currently owns the range to be transferred.
          
          The source group's current ownership must extend from exactly '--start' and/or up to exactly '--end'. In other words, this transfer cannot leave a gap in the source group's owned range.

      --destination <DESTINATION>
          ID of group that should be the new owner of the range.
          
          The destination group must currently own either nothing or an adjacent range.

      --start <START>
          The first record ID in the range, in hex.
          
          Example: 0000000000000000000000000000000000000000000000000000000000000000

      --end <END>
          The last record ID in the range (inclusive), in hex.
          
          Example: 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

  -h, --help
          Print help (see a summary with '-h')

```

## `cluster user-summary --help`

```
Report counts of active users by tenant for a month. These are users that have a secret stored at some point during the month (in the UTC timezone)

Usage: cluster user-summary [OPTIONS]

Options:
      --realm <REALM>  Restrict the report to just these realms(s). If not set will report on realms that are found via service discovery
      --when <WHEN>    What time period to report on [default: this-month] [possible values: this-month, last-month]
      --start <START>  The starting date (inclusive) of a custom time period to report on. format yyyy-mm-dd
      --end <END>      The ending date (exclusive) of a custom time period to report on
  -h, --help           Print help

```

