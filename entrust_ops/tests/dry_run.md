_This file is automatically generated._

## `entrust_ops feature activate certificate.txt`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Feature(
        Activate {
            certificate_file: "certificate.txt",
        },
    ),
}

Not checking if "certificate.txt" file is readable because --dry-run
Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/fet",
    args: [
        "--cert",
        "certificate.txt",
        "--reset-module",
    ],
    dir: None,
}
```

## `entrust_ops feature info`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Feature(
        Info,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/fet",
    args: [
        "--show-only",
    ],
    dir: None,
}
```

## `entrust_ops firmware file-info firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Firmware(
        FileInfo {
            file: "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff",
        },
    ),
}

Not computing file digest for "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff" because --dry-run
File "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff"
SHA-256: abaddecafc0ffee1abaddecafc0ffee2abaddecafc0ffee3abaddecafc0ffee4

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/loadrom",
    args: [
        "--view",
        "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff",
    ],
    dir: None,
}
```

## `entrust_ops firmware write firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Firmware(
        Write {
            file: "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff",
        },
    ),
}

Not computing file digest for "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff" because --dry-run
File "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff"
SHA-256: abaddecafc0ffee1abaddecafc0ffee2abaddecafc0ffee3abaddecafc0ffee4

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/loadrom",
    args: [
        "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff",
    ],
    dir: None,
}
```

## `entrust_ops hsm create-world`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        CreateWorld {
            debugging: false,
        },
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/new-world",
    args: [
        "--initialize",
        "--no-remoteshare-cert",
        "--no-recovery",
        "--acs-quorum",
        "1/1",
    ],
    dir: None,
}
```

## `entrust_ops hsm create-world --debugging`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        CreateWorld {
            debugging: true,
        },
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/new-world",
    args: [
        "--initialize",
        "--no-remoteshare-cert",
        "--no-recovery",
        "--acs-quorum",
        "1/1",
        "dseeall",
    ],
    dir: None,
}
```

## `entrust_ops hsm erase`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        Erase,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/initunit",
    args: [
        "--strong-kml",
    ],
    dir: None,
}
```

## `entrust_ops hsm info`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        Info,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/enquiry",
    args: [],
    dir: None,
}
```

## `entrust_ops hsm join-world`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        JoinWorld,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/new-world",
    args: [
        "--program",
        "--no-remoteshare-cert",
    ],
    dir: None,
}
```

## `entrust_ops hsm restart`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        Restart {
            mode: Operational,
        },
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/nopclearfail",
    args: [
        "--all",
        "--operational",
        "--wait",
    ],
    dir: None,
}
```

## `entrust_ops hsm restart --mode initialization`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        Restart {
            mode: Initialization,
        },
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/nopclearfail",
    args: [
        "--all",
        "--initialization",
        "--wait",
    ],
    dir: None,
}
```

## `entrust_ops hsm restart --mode maintenance`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        Restart {
            mode: Maintenance,
        },
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/nopclearfail",
    args: [
        "--all",
        "--maintenance",
        "--wait",
    ],
    dir: None,
}
```

## `entrust_ops hsm world-info`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Hsm(
        WorldInfo,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/nfkminfo",
    args: [],
    dir: None,
}
```

## `entrust_ops meta hash`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Meta(
        Hash,
    ),
}

Not computing file digest for "/proc/self/exe" because --dry-run
File "/proc/self/exe"
SHA-256: abaddecafc0ffee1abaddecafc0ffee2abaddecafc0ffee3abaddecafc0ffee4

```

## `entrust_ops meta paths`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Meta(
        Paths,
    ),
}

Environment variables:
    ENTRUST_INIT is "/home/entrust_ops_test/juicebox-hsm-realm/target/release/entrust_init"
    SIGNING_DIR is "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release"

Paths {
    entrust_init: "/home/entrust_ops_test/juicebox-hsm-realm/target/release/entrust_init",
    nfast_dir: "/opt/nfast",
    nfast_bin: "/opt/nfast/bin",
    signing_dir: "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release",
    world_dir: "/opt/nfast/kmdata/local",
}
```

## `entrust_ops realm create-nvram-file --signing-key-hash bdbef7d2e6a0dfefb7af3074adbaed97553e64cc`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Realm(
        CreateNvramFile {
            signing_key_hash: "bdbef7d2e6a0dfefb7af3074adbaed97553e64cc",
        },
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/home/entrust_ops_test/juicebox-hsm-realm/target/release/entrust_init",
    args: [
        "--signing",
        "bdbef7d2e6a0dfefb7af3074adbaed97553e64cc",
        "nvram",
    ],
    dir: None,
}
```

## `entrust_ops realm create-keys`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Realm(
        CreateKeys,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/home/entrust_ops_test/juicebox-hsm-realm/target/release/entrust_init",
    args: [
        "keys",
    ],
    dir: None,
}
```

## `entrust_ops realm noise-public-key`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Realm(
        NoisePublicKey,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/display-pubkey",
    args: [
        "simple",
        "jbox-noise",
    ],
    dir: None,
}
```

## `entrust_ops realm print-acl noise`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Realm(
        PrintAcl {
            key: Noise,
        },
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/home/entrust_ops_test/juicebox-hsm-realm/target/release/entrust_init",
    args: [
        "acl",
        "simple",
        "jbox-noise",
    ],
    dir: None,
}
```

## `entrust_ops sign create-key`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Sign(
        CreateKey,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/generatekey",
    args: [
        "--batch",
        "--cardset",
        "codesign",
        "seeinteg",
        "recovery=no",
        "size=4096",
        "type=RSA",
        "plainname=jbox-signer",
    ],
    dir: None,
}
```

## `entrust_ops sign key-info`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Sign(
        KeyInfo,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/nfkminfo",
    args: [
        "--key-list",
        "seeinteg",
        "jbox-signer",
    ],
    dir: None,
}
```

## `entrust_ops sign software`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Sign(
        Software {
            input: "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.elf",
            output: "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.sar",
        },
    ),
}

Not computing file digest for "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.elf" because --dry-run
File "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.elf"
SHA-256: abaddecafc0ffee1abaddecafc0ffee2abaddecafc0ffee3abaddecafc0ffee4

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/tct2",
    args: [
        "--sign-and-pack",
        "--infile",
        "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.elf",
        "--outfile",
        "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.sar",
        "--key",
        "jbox-signer",
        "--is-machine",
        "--machine-type",
        "PowerPCELF",
        "--non-interactive",
        "--show-metadata",
    ],
    dir: None,
}

Not computing file digest for "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.sar" because --dry-run
File "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.sar"
SHA-256: abaddecafc0ffee1abaddecafc0ffee2abaddecafc0ffee3abaddecafc0ffee4

```

## `entrust_ops sign userdata`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Sign(
        Userdata {
            tempfile: "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.dummy",
            output: "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.sar",
        },
    ),
}

Not removing "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.dummy" because --dry-run
Not creating "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.dummy" file with mode 0o444 because --dry-run

Not computing file digest for "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.dummy" because --dry-run
File "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.dummy"
SHA-256: b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259
Matches expected digest


Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/tct2",
    args: [
        "--sign-and-pack",
        "--infile",
        "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.dummy",
        "--outfile",
        "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.sar",
        "--key",
        "jbox-signer",
        "--machine-key-ident",
        "jbox-signer",
        "--machine-type",
        "PowerPCELF",
        "--non-interactive",
        "--show-metadata",
    ],
    dir: None,
}

Not computing file digest for "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.sar" because --dry-run
File "/home/entrust_ops_test/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.sar"
SHA-256: abaddecafc0ffee1abaddecafc0ffee2abaddecafc0ffee3abaddecafc0ffee4

```

## `entrust_ops smartcard erase`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Smartcard(
        Erase,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/slotinfo",
    args: [
        "--format",
        "--ignoreauth",
        "--module",
        "1",
        "--slot",
        "0",
    ],
    dir: None,
}
```

## `entrust_ops smartcard info`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Smartcard(
        Info,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/slotinfo",
    args: [
        "--module",
        "1",
        "--slot",
        "0",
    ],
    dir: None,
}
```

## `entrust_ops smartcard write-ocs`

#### stdout

```perl
Args {
    common: CommonArgs {
        dry_run: true,
    },
    command: Smartcard(
        WriteOcs,
    ),
}

Not running because --dry-run:
Spawning Process {
    program: "/opt/nfast/bin/createocs",
    args: [
        "--module",
        "1",
        "--name",
        "codesign",
        "--ocs-quorum",
        "1/1",
        "--no-persist",
        "--no-pp-recovery",
        "--timeout",
        "0",
    ],
    dir: None,
}
```
