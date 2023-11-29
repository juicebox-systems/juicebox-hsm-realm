# Entrust Ops Tool

This tool is a wrapper for running Entrust commands, providing convenience and
safety. It's specialized to our usage and opinionated on the commands, so that
few flags need to be typed on the command line. For an overview of available
commands, see [`usage.md`](usage.md).

All commands can execute in a dry run mode, which prints what they would do. To
review what all the commands do in the common case, see
[`tests/dry_run.md`](tests/dry_run.md).

This tool is based on the key ceremony tool. The two are expected to diverge
somewhat, since they serve different purposes. The ceremony tool needs to
remain strictly limited to its ceremony purposes to be easy to audit, while
this tool can grow to contain anything we find generally useful in a wider
variety of environments. However, wherever possible, we should aim to maintain
compatibility between the tools and invoke the same Entrust commands and flags.
