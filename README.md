# `delorean`: a client for Temporal's historical account data service service

`delorean` is a client for penrose — Temporal's historical account data service — which is currently in alpha with a handful of testers.

## Usage

To use the delorean client, clone the repo and

```bash
cargo install --path delorean-client
```

Once installed, use via:

```bash
delorean <SIGNATURE> <TEMPORAL_PENROSE_URL>
```

To try swapping programs, use

```bash
delorean <SIGNATURE> <TEMPORAL_PENROSE_URL> --replace-program=<PUBKEY>:<PATH_TO_REPLACEMENT>
```

This is just a reference client implementation. Feel free to create other clients that store fixtures or swap/mutate non-program accounts as well, etc
