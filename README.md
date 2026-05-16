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

## Example Output

```
fetching fixture for WRM4dvtB32k261TTsn2nc4ini9VvWrB1NBLCQdtZk1FRycp54VTuaDikufLk1E2MANthZjQQS6skzeis2W3bvNA

--- fixture ---
  schema_version  : 0
  slot            : 420195494
  client_version  : 4.2.0-alpha.0
  enabled features: 221
  pre-accounts    : 25
  post-accounts   : 25
  loader-v3 progs : 3
  sysvars         : 9
  alt writable    : 3
  alt readonly    : 8
  expected CUs    : 104291

building SVM environment...
sanitizing transaction...
executing...

--- replay outcome ---
  actual status   : Ok(())
  expected status : Ok(())
  status          : MATCH
  actual CUs      : 104291
  expected CUs    : 104291
  CUs             : MATCH
  post-state      : MATCH

  log messages (61):
    Program ComputeBudget111111111111111111111111111111 invoke [1]
    Program ComputeBudget111111111111111111111111111111 success
    Program ComputeBudget111111111111111111111111111111 invoke [1]
    Program ComputeBudget111111111111111111111111111111 success
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL invoke [1]
    Program log: CreateIdempotent
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 179 of 1394349 compute units
    Program return: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA pQAAAAAAAAA=
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success
    Program 11111111111111111111111111111111 invoke [2]
    Program 11111111111111111111111111111111 success
    Program log: Initialize the associated token account
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 37 of 1389260 compute units
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 229 of 1386799 compute units
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL consumed 13413 of 1399700 compute units
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL success
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL invoke [1]
    Program log: CreateIdempotent
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL consumed 4338 of 1386287 compute units
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL success
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL invoke [1]
    Program log: CreateIdempotent
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL consumed 4437 of 1381949 compute units
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL success
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL invoke [1]
    Program log: CreateIdempotent
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL consumed 4437 of 1377512 compute units
    Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL success
    Program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA invoke [1]
    Program log: Instruction: Buy
    Program pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ invoke [2]
    Program log: Instruction: GetFees
    Program pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ consumed 5660 of 1327570 compute units
    Program return: pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ GQAAAAAAAAAFAAAAAAAAAAAAAAAAAAAA
    Program pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ success
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 112 of 1318109 compute units
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 105 of 1315251 compute units
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 105 of 1312146 compute units
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 105 of 1307518 compute units
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success
    Program data: Z/RSHyz1d3dz2QhqAAAAAIlT08wAAAAAu4iN+3gFAAAAAAAAAAAAANrNfmz/CAAAMc0Yx1QAAAA+gP327zICAKLcEQhdBQAAGQAAAAAAAAATfL1uAwAAAAUAAAAAAAAAN3+/rwAAAAC1WM92YAUAAOzXjiZhBQAAsGUInXoCk/QMsjcEDBh9CQnnpPhkG25HL/9NO+UfeVdpPrc1Hghz9vluaxlB08BsJQVbEsbUIWPQqQ+moYorLbRxrYn/ubvmBZ+Q1RJaksUgpaFpdmpJcoEUQ4B1cxELusKwC4ywl9sXAhE4ngaK3hWGKIgpk2MnDK2PgdaSQN3/g4OBi6j6KMPNO21ek/n6uPCXm8NyFazFskaHe6jDySS6z0adxy9pIw60Bkxx2FazNrIDZqSnspCqtpvp4RMLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiVPTzAAAAAADAAAAYnV5AAAAAAAAAAAAAAAAAAAAAIgTAAAAAAAAm7/fVwAAAAA=
    Program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA invoke [2]
    Program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA consumed 2054 of 1299828 compute units
    Program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA success
    Program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA consumed 77248 of 1373075 compute units
    Program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA success
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 118 of 1295827 compute units
    Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success

--- return data ---
  expected program : 11111111111111111111111111111111
  expected data len: 0
  actual           : <none>
  return data      : MATCH

--- post-account state (fixture vs replay loaded accounts) ---
  all 25 fixture post_account entries: MATCH replay state
```



