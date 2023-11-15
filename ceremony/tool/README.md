# Key Ceremony Tool

This tool is used during HSM key ceremonies to run pre-determined commands.
It's very opinionated on the commands, so that few flags need to be typed on
the command line during a ceremony. For an overview of available commands, see
[`usage.md`](usage.md).

All commands can execute in a dry run mode, which prints what they would do. To
review what all the commands do in the common case, see
[`tests/dry_run.md`](tests/dry_run.md).
