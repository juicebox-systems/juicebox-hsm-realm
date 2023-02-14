
## Local Bigtable emulator

You'll need the Bigtable emulator and the Cloud Bigtable CLI tool to run
offline. You can install these either using the hefty `gcloud` SDK or using the
Go compiler.

### Option 1: Install using the `gcloud` SDK:

Follow the [gcloud CLI installation instructions](https://cloud.google.com/sdk/docs/install).

Run:

```sh
gcloud components update beta
gcloud components install cbt
```

And start the emulator:

```sh
gcloud beta emulators bigtable start --host-port localhost:9000
```

### Option 2: Install using Go:

Run:

```sh
go install cloud.google.com/go/bigtable/cmd/emulator@latest
go install cloud.google.com/go/cbt@latest
```

And start the emulator:

```sh
emulator -host localhost -port 9000
```

### Create a table

`cbt` is a Cloud Bigtable CLI tool. We'll make an alias for using it with the
local emulator, then create a table.

```sh
alias lbt='BIGTABLE_EMULATOR_HOST=localhost:9000 cbt -creds /dev/null -project prj -instance inst'
lbt createtable tab families=fam
lbt ls
```

Now you can run the MVP locally.
