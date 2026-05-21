use {
    agave_feature_set::FeatureSet,
    agave_precompiles::{get_precompile, get_precompiles, is_precompile},
    agave_penrose_types::{
        FixtureAccount, FixtureProgramData, FixtureSysvar, TransactionFixture,
        TransactionFixturesBatch,
    },
    agave_reserved_account_keys::ReservedAccountKeys,
    agave_syscalls::{
        create_program_runtime_environment_v1, create_program_runtime_environment_v2,
    },
    ahash::{AHashMap, AHashSet},
    base64::prelude::*,
    flate2::read::GzDecoder,
    serde_json::json,
    solana_account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
    solana_bpf_loader_program as _,
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_compute_budget_instruction::instructions_processor::process_compute_budget_instructions,
    solana_fee_structure::FeeDetails,
    solana_loader_v3_interface::{get_program_data_address, state::UpgradeableLoaderState},
    solana_loader_v4_interface::state::LoaderV4State,
    solana_message::{SimpleAddressLoader, v0::LoadedAddresses},
    solana_program_runtime::{
        execution_budget::{
            MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES, SVMTransactionExecutionAndFeeBudgetLimits,
            SVMTransactionExecutionBudget,
        },
        invoke_context::BuiltinFunctionWithContext,
        loaded_programs::{BlockRelation, ForkGraph, ProgramCacheEntry},
    },
    solana_precompile_error::PrecompileError,
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_sdk_ids::{
        bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, compute_budget, loader_v4,
        native_loader, vote,
    },
    solana_signature::Signature,
    solana_svm::{
        account_loader::CheckedTransactionDetails,
        rent_calculator::RENT_EXEMPT_RENT_EPOCH,
        transaction_execution_result::ExecutedTransaction,
        transaction_processing_result::ProcessedTransaction,
        transaction_processor::{
            ExecutionRecordingConfig, TransactionBatchProcessor, TransactionProcessingConfig,
            TransactionProcessingEnvironment,
        },
    },
    solana_svm_callback::{AccountState, InvokeContextCallback, TransactionProcessingCallback},
    solana_svm_feature_set::SVMFeatureSet,
    solana_svm_transaction::svm_message::{SVMMessage, SVMStaticMessage},
    solana_transaction::{sanitized::SanitizedTransaction, versioned::VersionedTransaction},
    solana_transaction_context::transaction::TransactionReturnData,
    solana_transaction_error::TransactionError,
    std::{
        cmp::Ordering,
        collections::HashMap,
        env, fs,
        io::{IsTerminal, Read, stdout},
        path::{Path, PathBuf},
        process,
        sync::{Arc, RwLock},
        time::{Duration, Instant},
    },
};

mod synthetic_accounts;

const DEFAULT_RPC_URL: &str = "http://localhost:8899";
/// Large block batches can take a while to serialize and gzip on penrose-server.
const PENROSE_RPC_TIMEOUT: Duration = Duration::from_secs(300);

type RpcError = Box<dyn std::error::Error>;

struct RpcTransfer {
    wire_bytes: usize,
    json_bytes: usize,
}

impl RpcTransfer {
    /// Negative when gzip shrinks the HTTP body (e.g. -93% = wire is 93% smaller than JSON).
    fn wire_size_pct(&self) -> f64 {
        if self.json_bytes == 0 {
            return 0.0;
        }
        (self.wire_bytes as f64 / self.json_bytes as f64 - 1.0) * 100.0
    }

    fn log_suffix(&self) -> String {
        if self.wire_bytes < self.json_bytes {
            format!(
                "; {} B wire → {} B json ({:+.1}% wire size)",
                self.wire_bytes,
                self.json_bytes,
                self.wire_size_pct()
            )
        } else {
            String::new()
        }
    }
}

struct RpcCall<T> {
    value: T,
    transfer: RpcTransfer,
}

struct JsonRpcClient {
    url: String,
    client: reqwest::blocking::Client,
}

impl JsonRpcClient {
    fn new(url: impl ToString) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(PENROSE_RPC_TIMEOUT)
            .gzip(false)
            .build()
            .expect("build json-rpc client");
        Self {
            url: url.to_string(),
            client,
        }
    }

    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<RpcCall<serde_json::Value>, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        });
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .json(&body)
            .send()?;
        let gzip = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("gzip"));
        let wire_bytes = response.bytes()?.to_vec();
        let wire_len = wire_bytes.len();
        let json_bytes = if gzip {
            let mut decoder = GzDecoder::new(wire_bytes.as_slice());
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        } else {
            wire_bytes
        };
        let json_len = json_bytes.len();
        let resp: serde_json::Value = serde_json::from_slice(&json_bytes)?;
        if let Some(err) = resp.get("error") {
            return Err(format!("json-rpc {method} error: {err}").into());
        }
        Ok(RpcCall {
            value: resp["result"].clone(),
            transfer: RpcTransfer {
                wire_bytes: wire_len,
                json_bytes: json_len,
            },
        })
    }
}

fn block_transaction_base64(tx: &serde_json::Value) -> Option<&str> {
    let field = tx.get("transaction")?;
    if let Some(arr) = field.as_array() {
        arr.first()?.as_str()
    } else {
        field.as_str()
    }
}

fn fetch_non_vote_signatures_from_block(
    rpc_url: &str,
    slot: u64,
) -> Result<(Vec<Signature>, u32, u32), RpcError> {
    let rpc = JsonRpcClient::new(rpc_url);
    let RpcCall {
        value: result,
        transfer: _,
    } = rpc.call(
        "getBlock",
        json!([
            slot,
            {
                "encoding": "base64",
                "transactionDetails": "full",
                "rewards": false,
                "maxSupportedTransactionVersion": 0,
                "commitment": "confirmed",
            }
        ]),
    )?;
    if result.is_null() {
        return Err(format!("getBlock: slot {slot} not available (null result)").into());
    }
    let txs = result
        .get("transactions")
        .and_then(|v| v.as_array())
        .ok_or("getBlock: missing transactions array")?;
    let mut signatures = Vec::new();
    let mut total_txs = 0u32;
    let mut vote_txs = 0u32;
    for tx in txs {
        total_txs += 1;
        let Some(b64) = block_transaction_base64(tx) else {
            continue;
        };
        let bytes = BASE64_STANDARD.decode(b64)?;
        let versioned: VersionedTransaction = bincode::deserialize(&bytes)?;
        if is_simple_vote_transaction(&versioned) {
            vote_txs += 1;
            continue;
        }
        if let Some(sig) = versioned.signatures.first() {
            signatures.push(*sig);
        }
    }
    Ok((signatures, total_txs, vote_txs))
}

/// Penrose captures non-vote transactions only; mirror the usual simple-vote check.
fn is_simple_vote_transaction(tx: &VersionedTransaction) -> bool {
    let keys = tx.message.static_account_keys();
    !tx.message.instructions().is_empty()
        && tx.message.instructions().iter().all(|ix| {
            keys.get(ix.program_id_index as usize)
                .map(|k| vote::check_id(k))
                .unwrap_or(false)
        })
}

fn get_transaction_fixture(
    rpc: &JsonRpcClient,
    signature: &Signature,
) -> Result<Option<TransactionFixture>, RpcError> {
    let total = Instant::now();
    let rpc_started = Instant::now();
    let RpcCall {
        value: result,
        transfer,
    } = rpc.call(
        "getTransactionFixture",
        json!([signature.to_string()]),
    )?;
    let rpc_elapsed = rpc_started.elapsed();
    let Some(b64) = result.as_str() else {
        println!(
            "fixture fetch: {:.3}s (rpc only, no fixture stored){}",
            rpc_elapsed.as_secs_f64(),
            transfer.log_suffix()
        );
        return Ok(None);
    };
    let decode_started = Instant::now();
    let bytes = BASE64_STANDARD
        .decode(b64)
        .map_err(|e| format!("getTransactionFixture: non-base64 payload: {e}"))?;
    let fixture = TransactionFixture::deserialize(&bytes)
        .map_err(|e| format!("getTransactionFixture: failed to decode fixture bytes: {e}"))?;
    let decode_elapsed = decode_started.elapsed();
    println!(
        "fixture fetch: {:.3}s total (rpc {:.3}s, decode {:.3}s; {} B base64, {} B fixture{})",
        total.elapsed().as_secs_f64(),
        rpc_elapsed.as_secs_f64(),
        decode_elapsed.as_secs_f64(),
        b64.len(),
        bytes.len(),
        transfer.log_suffix()
    );
    Ok(Some(fixture))
}

fn get_transaction_fixtures_batch(
    rpc: &JsonRpcClient,
    signatures: &[Signature],
    log_timing: bool,
) -> Result<TransactionFixturesBatch, RpcError> {
    let total = Instant::now();
    let sig_strings: Vec<String> = signatures.iter().map(|s| s.to_string()).collect();
    let rpc_started = Instant::now();
    let RpcCall {
        value: result,
        transfer,
    } = rpc.call("getTransactionFixtures", json!([sig_strings]))?;
    let encoded = result
        .as_str()
        .ok_or("getTransactionFixtures: expected base64 string result")?;
    let rpc_elapsed = rpc_started.elapsed();
    let decode_started = Instant::now();
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| format!("getTransactionFixtures: non-base64 payload: {e}"))?;
    let batch = TransactionFixturesBatch::deserialize(&bytes)
        .map_err(|e| format!("getTransactionFixtures: failed to decode batch bytes: {e}"))?;
    let decode_elapsed = decode_started.elapsed();
    let transfer_suffix = transfer.log_suffix();
    if log_timing {
        println!(
            "fixture batch fetch: {:.3}s total (rpc {:.3}s, decode {:.3}s; {} signatures, {} \
             unique blobs, {} B base64{})",
            total.elapsed().as_secs_f64(),
            rpc_elapsed.as_secs_f64(),
            decode_elapsed.as_secs_f64(),
            signatures.len(),
            batch.blobs.len(),
            encoded.len(),
            transfer_suffix
        );
    } else {
        println!(
            "fixture batch fetch: {} signatures, {} unique blobs, {} B base64{}",
            signatures.len(),
            batch.blobs.len(),
            encoded.len(),
            transfer_suffix
        );
    }
    Ok(batch)
}

struct BlockArgs {
    verbose: bool,
    slot: u64,
    solana_rpc_url: String,
    penrose_rpc_url: String,
}

fn parse_block_args(args: &[String]) -> Result<BlockArgs, String> {
    let mut verbose = false;
    let mut positional = Vec::new();
    for arg in args.iter().skip(2) {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            other => positional.push(other.to_string()),
        }
    }
    if positional.len() < 2 {
        return Err("expected <slot> and <solana_rpc_url>".into());
    }
    let slot: u64 = positional[0]
        .parse()
        .map_err(|e| format!("bad slot `{}`: {e}", positional[0]))?;
    let solana_rpc_url = positional[1].clone();
    let penrose_rpc_url = positional
        .get(2)
        .cloned()
        .or_else(|| env::var("PENROSE_RPC").ok())
        .unwrap_or_else(|| solana_rpc_url.clone());
    Ok(BlockArgs {
        verbose,
        slot,
        solana_rpc_url,
        penrose_rpc_url,
    })
}

struct ReplayCompare {
    status_match: Option<bool>,
    cu_match: Option<bool>,
    state_match: Option<bool>,
    pass: bool,
}

const BLOCK_SIG_WIDTH: usize = 88;
const BLOCK_STATUS_WIDTH: usize = 6;
const BLOCK_MATCH_WIDTH: usize = 5;
const BLOCK_RESULT_WIDTH: usize = 6;

fn color_enabled() -> bool {
    !env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
        && stdout().is_terminal()
}

fn colorize(text: &str, color: &str) -> String {
    if color_enabled() {
        format!("{color}{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn signature_cell(signature: &Signature) -> String {
    format!("{:<BLOCK_SIG_WIDTH$}", signature.to_string())
}

fn match_cell(m: Option<bool>, width: usize) -> String {
    let (label, color) = match m {
        Some(true) => ("match", "\x1b[32m"),
        Some(false) => ("miss", "\x1b[31m"),
        None => ("n/a", "\x1b[90m"),
    };
    colorize(&format!("{label:>width$}"), color)
}

fn result_cell(pass: bool) -> String {
    let (label, color) = if pass {
        ("PASS", "\x1b[32m")
    } else {
        ("FAIL", "\x1b[31m")
    };
    colorize(&format!("{label:>BLOCK_RESULT_WIDTH$}"), color)
}

fn print_block_table_header() {
    let header = format!(
        "{:<BLOCK_SIG_WIDTH$} {:>BLOCK_STATUS_WIDTH$} {:>BLOCK_MATCH_WIDTH$} \
         {:>BLOCK_MATCH_WIDTH$} {:>BLOCK_RESULT_WIDTH$}",
        "SIGNATURE",
        "STATUS",
        "CU",
        "STATE",
        "RESULT"
    );
    println!("{}", colorize(&header, "\x1b[1m"));
}

fn print_block_table_row(signature: &Signature, cmp: &ReplayCompare) {
    println!(
        "{} {} {} {} {}",
        signature_cell(signature),
        match_cell(cmp.status_match, BLOCK_STATUS_WIDTH),
        match_cell(cmp.cu_match, BLOCK_MATCH_WIDTH),
        match_cell(cmp.state_match, BLOCK_MATCH_WIDTH),
        result_cell(cmp.pass),
    );
}

fn fixture_expected_status(fixture: &TransactionFixture) -> Result<(), TransactionError> {
    bincode::deserialize(&fixture.result.status)
        .unwrap_or(Err(TransactionError::AccountNotFound))
}

fn compare_replay(
    fixture: &TransactionFixture,
    message: &SanitizedTransaction,
    results: &[solana_svm::transaction_processing_result::TransactionProcessingResult],
) -> ReplayCompare {
    let expected_status = fixture_expected_status(fixture);
    let expected_cus = fixture.result.compute_units_consumed;

    let Some(result) = results.first() else {
        return ReplayCompare {
            status_match: None,
            cu_match: None,
            state_match: None,
            pass: false,
        };
    };

    match result {
        Ok(ProcessedTransaction::Executed(exec)) => {
            let exec = exec.as_ref();
            let actual_status = exec.execution_details.status.clone();
            let status_match = actual_status.clone().map(|_| ()) == expected_status;
            let actual_cus = exec.execution_details.executed_units;
            let cu_match = actual_cus == expected_cus;
            let (post_mismatches, _) = post_account_mismatches(fixture, exec, message);
            let state_match = post_mismatches.is_empty();
            let pass = status_match && cu_match && state_match;
            ReplayCompare {
                status_match: Some(status_match),
                cu_match: Some(cu_match),
                state_match: Some(state_match),
                pass,
            }
        }
        Ok(ProcessedTransaction::FeesOnly(_)) | Err(_) => ReplayCompare {
            status_match: Some(false),
            cu_match: None,
            state_match: None,
            pass: false,
        },
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

#[derive(Clone, Debug)]
struct ProgramReplacement {
    program_id: Pubkey,
    elf_path: PathBuf,
}

fn parse_one_program_replacement(
    spec: &str,
    flag_span: &str,
) -> Result<ProgramReplacement, String> {
    let (key, path) = spec
        .split_once(':')
        .ok_or_else(|| format!("--replace-program: expected <PUBKEY>:<PATH>, got `{flag_span}`"))?;
    let program_id: Pubkey = key
        .parse()
        .map_err(|e| format!("--replace-program: bad pubkey `{key}`: {e}"))?;
    Ok(ProgramReplacement {
        program_id,
        elf_path: PathBuf::from(path),
    })
}

fn parse_args(args: &[String]) -> Result<(Signature, String, Vec<ProgramReplacement>), String> {
    let mut replace_programs = Vec::new();
    let mut positionals = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if let Some(rest) = arg.strip_prefix("--replace-program=") {
            replace_programs.push(parse_one_program_replacement(rest, arg)?);
            i += 1;
        } else if arg == "--replace-program" {
            let next = args
                .get(i + 1)
                .ok_or_else(|| "--replace-program: missing value <PUBKEY>:<PATH>".to_string())?;
            replace_programs.push(parse_one_program_replacement(next, next)?);
            i += 2;
        } else {
            positionals.push(arg.clone());
            i += 1;
        }
    }

    if positionals.is_empty() {
        return Err(
            "missing <signature_base58> (place after flags, or pass at least one positional)"
                .to_string(),
        );
    }

    let signature: Signature = positionals[0]
        .parse()
        .map_err(|e| format!("bad signature: {e}"))?;
    let rpc_url = positionals
        .get(1)
        .cloned()
        .unwrap_or_else(|| DEFAULT_RPC_URL.into());

    Ok((signature, rpc_url, replace_programs))
}

fn read_replacement_elf(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fs::read(path)
        .map_err(|e| format!("--replace-program: cannot read ELF {}: {e}", path.display()).into())
}

fn apply_program_replacements(
    bank: &MockBank,
    rent: &Rent,
    replacements: &[ProgramReplacement],
) -> Result<(), Box<dyn std::error::Error>> {
    if replacements.is_empty() {
        return Ok(());
    }

    let mut accounts = bank.accounts.write().unwrap();

    for rep in replacements {
        let program_account = accounts.get(&rep.program_id).cloned().ok_or_else(|| {
            format!(
                "--replace-program: no account for program id {}",
                rep.program_id
            )
        })?;

        let elf = read_replacement_elf(&rep.elf_path)?;

        let owner = *program_account.owner();

        if bpf_loader_upgradeable::check_id(&owner) {
            let programdata_address = match bincode::deserialize(program_account.data()) {
                Ok(UpgradeableLoaderState::Program {
                    programdata_address,
                }) => programdata_address,
                Ok(other) => {
                    return Err(format!(
                        "--replace-program: {} is not a loader-v3 Program account (state: \
                         {other:?})",
                        rep.program_id
                    )
                    .into());
                }
                Err(_) => {
                    return Err(format!(
                        "--replace-program: cannot deserialize loader-v3 program account {}",
                        rep.program_id
                    )
                    .into());
                }
            };

            let programdata_account =
                accounts.get(&programdata_address).cloned().ok_or_else(|| {
                    format!(
                        "--replace-program: missing programdata account {programdata_address} for \
                         {}",
                        rep.program_id
                    )
                })?;

            let meta_len = UpgradeableLoaderState::size_of_programdata_metadata();
            let pdata = programdata_account.data();
            let header_state: UpgradeableLoaderState =
                bincode::deserialize(pdata.get(..meta_len).ok_or_else(|| {
                    format!(
                        "--replace-program: programdata for {} too small",
                        rep.program_id
                    )
                })?)
                .map_err(|_| {
                    format!(
                        "--replace-program: cannot parse programdata header for {}",
                        rep.program_id
                    )
                })?;

            let (slot, upgrade_authority_address) = match header_state {
                UpgradeableLoaderState::ProgramData {
                    slot,
                    upgrade_authority_address,
                } => (slot, upgrade_authority_address),
                other => {
                    return Err(format!(
                        "--replace-program: programdata for {} is not ProgramData (got {other:?})",
                        rep.program_id
                    )
                    .into());
                }
            };

            let mut new_programdata = bincode::serialize(&UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority_address,
            })?;
            new_programdata.extend_from_slice(&elf);

            let min_lamports = rent.minimum_balance(new_programdata.len());
            let mut updated = programdata_account;
            updated.set_lamports(updated.lamports().max(min_lamports));
            updated.set_data_from_slice(&new_programdata);
            accounts.insert(programdata_address, updated);
            continue;
        }

        if bpf_loader::check_id(&owner) || bpf_loader_deprecated::check_id(&owner) {
            let min_lamports = rent.minimum_balance(elf.len()).max(1);
            let mut updated = program_account;
            updated.set_lamports(updated.lamports().max(min_lamports));
            updated.set_data_from_slice(&elf);
            accounts.insert(rep.program_id, updated);
            continue;
        }

        if loader_v4::check_id(&owner) {
            let offset = LoaderV4State::program_data_offset();
            let header = program_account
                .data()
                .get(..offset)
                .ok_or_else(|| {
                    format!(
                        "--replace-program: loader-v4 account {} too small",
                        rep.program_id
                    )
                })?
                .to_vec();
            let mut new_data = header;
            new_data.extend_from_slice(&elf);
            let min_lamports = rent.minimum_balance(new_data.len());
            let mut updated = program_account;
            updated.set_lamports(updated.lamports().max(min_lamports));
            updated.set_data_from_slice(&new_data);
            accounts.insert(rep.program_id, updated);
            continue;
        }

        return Err(format!(
            "--replace-program: {} has unsupported loader owner {}",
            rep.program_id, owner
        )
        .into());
    }

    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("block") {
        return run_block(&args);
    }
    run_replay(&args)
}

fn run_block(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let block_args = match parse_block_args(args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!(
                "usage: {} block [-v] <slot> <solana_rpc_url> [penrose_rpc_url]\n\n  -v  verbose \
                 replay (fixture summary, logs, account diffs)\n\n  slot             block slot to \
                 load via getBlock\n  solana_rpc_url   JSON-RPC for getBlock (validator)\n  \
                 penrose_rpc_url  JSON-RPC for getTransactionFixtures (penrose-server); defaults \
                 to $PENROSE_RPC or solana_rpc_url\n\nerror: {msg}",
                args.first().map(String::as_str).unwrap_or("delorean"),
            );
            process::exit(2);
        }
    };
    let BlockArgs {
        verbose,
        slot,
        solana_rpc_url,
        penrose_rpc_url,
    } = block_args;

    if verbose {
        println!("connecting to {solana_rpc_url} for getBlock");
    }
    let (signatures, total_txs, vote_txs) =
        fetch_non_vote_signatures_from_block(&solana_rpc_url, slot)?;

    println!(
        "block {slot}: {total_txs} transactions, {vote_txs} votes skipped, {} non-vote",
        signatures.len()
    );

    if signatures.is_empty() {
        return Ok(());
    }

    if verbose {
        println!("connecting to {penrose_rpc_url} for getTransactionFixtures");
    }
    let penrose_rpc = JsonRpcClient::new(penrose_rpc_url);
    let batch = get_transaction_fixtures_batch(&penrose_rpc, &signatures, verbose)?;
    if batch.fixtures.len() != signatures.len() {
        return Err(format!(
            "getTransactionFixtures returned {} fixtures for {} signatures",
            batch.fixtures.len(),
            signatures.len()
        )
        .into());
    }

    let mut present = 0u32;
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut missing = 0u32;
    let mut replayed = 0u32;
    if !verbose {
        print_block_table_header();
    }
    for (signature, entry) in signatures.iter().zip(batch.fixtures.iter()) {
        let Some(batch_fixture) = entry else {
            missing += 1;
            if verbose {
                println!("{signature}: no penrose fixture");
            } else {
                print_block_table_row(
                    signature,
                    &ReplayCompare {
                        status_match: None,
                        cu_match: None,
                        state_match: None,
                        pass: false,
                    },
                );
            }
            continue;
        };
        present += 1;
        let fixture = batch_fixture.clone().into_inlined(&batch.blobs);
        if verbose {
            println!("\n========== {signature} ==========");
            print_fixture_summary(&fixture);
            replay_fixture(&fixture, &[], true)?;
            replayed += 1;
            continue;
        }
        match execute_fixture(&fixture, &[], verbose) {
            Ok((sanitized, results)) => {
                let cmp = compare_replay(&fixture, &sanitized, &results);
                if cmp.pass {
                    pass += 1;
                } else {
                    fail += 1;
                }
                print_block_table_row(signature, &cmp);
            }
            Err(_) => {
                fail += 1;
                print_block_table_row(
                    signature,
                    &ReplayCompare {
                        status_match: Some(false),
                        cu_match: None,
                        state_match: None,
                        pass: false,
                    },
                );
            }
        }
    }

    if verbose {
        println!(
            "\nblock {slot} done: {} non-vote txs, {present} fixtures present, {replayed} replayed, {missing} missing",
            signatures.len()
        );
    } else {
        println!(
            "block {slot} done: {} non-vote, {present} fixtures, {pass} pass, {fail} fail, {missing} missing",
            signatures.len()
        );
    }
    Ok(())
}

fn run_replay(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (signature, rpc_url, replace_programs) = match parse_args(args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!(
                "usage: {} [replay] [--replace-program=<PUBKEY>:<PATH> | --replace-program \
                     <PUBKEY>:<PATH> ...] <signature_base58> [rpc_url]\n       {} block [-v] <slot> \
                     <solana_rpc_url> [penrose_rpc_url]\n\nreplay:\n  signature_base58  tx to \
                     replay\n  rpc_url           penrose-server JSON-RPC; defaults to \
                     {DEFAULT_RPC_URL}\n\nblock:\n  fetches getBlock, skips votes, batch-fetches \
                     fixtures via getTransactionFixtures, replays each present fixture\n  default: \
                     one line per tx (signature status cus state PASS|FAIL); -v for full output\n\n\
                     options:\n  -v (block)        verbose block replay\n  --replace-program  replace \
                     deployed ELF before replay (replay mode only)\n\n\
                     error: {msg}",
                args.first().map(String::as_str).unwrap_or("delorean"),
                args.first().map(String::as_str).unwrap_or("delorean"),
            );
            process::exit(2);
        }
    };

    println!("connecting to {rpc_url}");
    let rpc = JsonRpcClient::new(rpc_url);

    println!("fetching fixture for {signature}");
    let fixture = get_transaction_fixture(&rpc, &signature)?.ok_or(
        "no fixture stored for that signature (never captured, evicted, or not yet finalized)",
    )?;

    print_fixture_summary(&fixture);
    replay_fixture(&fixture, &replace_programs, true)?;
    Ok(())
}

fn print_instructions_after_sanitization(tx: &SanitizedTransaction) {
    println!("\n--- instructions (after sanitization) ---");
    let account_keys = tx.account_keys();
    for (ix_index, (program_id, instruction)) in tx.program_instructions_iter().enumerate() {
        let data_hex: String = if instruction.data.is_empty() {
            "(empty)".to_string()
        } else {
            instruction
                .data
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        println!("ix {ix_index}");
        println!("  program: {program_id}");
        println!("  data:    {data_hex}");
        println!("  accounts:");
        if instruction.accounts.is_empty() {
            println!("    (none — precompile instructions use data only)");
        } else {
            println!("    {:<44} {:>6} {:>8}", "key", "signer", "writable");
        }
        for account_index in instruction.accounts.iter() {
            let account_index = usize::from(*account_index);
            let key = account_keys
                .get(account_index)
                .expect("instruction account index in message account list");
            println!(
                "    {:<44} {:>6} {:>8}",
                key,
                tx.is_signer(account_index),
                tx.is_writable(account_index),
            );
        }
    }
}

fn execute_fixture(
    fixture: &TransactionFixture,
    replace_programs: &[ProgramReplacement],
    log_instructions: bool,
) -> Result<
    (
        SanitizedTransaction,
        Vec<solana_svm::transaction_processing_result::TransactionProcessingResult>,
    ),
    Box<dyn std::error::Error>,
> {
    let rent = extract_rent(&fixture.sysvars);
    let (agave_feature_set, feature_set) = feature_sets_from_fixture(&fixture.enabled_features);
    let bank = build_mock_bank(fixture, agave_feature_set.clone());
    apply_program_replacements(&bank, &rent, replace_programs)?;
    let svm_budget =
        SVMTransactionExecutionBudget::new_with_defaults(feature_set.raise_cpi_nesting_limit_to_8);

    let fork_graph = Arc::new(RwLock::new(ReplayForkGraph));
    let loader_v1 = Arc::new(create_program_runtime_environment_v1(
        &feature_set,
        &svm_budget,
        false,
        false,
    )?);
    let loader_v2 = Arc::new(create_program_runtime_environment_v2(&svm_budget, false));
    let mut batch_processor = TransactionBatchProcessor::<ReplayForkGraph>::new(
        fixture.slot,
        0,
        Arc::downgrade(&fork_graph),
        Some(loader_v1),
        Some(loader_v2),
    );
    let simd_0268_active =
        agave_feature_set.is_active(&agave_feature_set::raise_cpi_nesting_limit_to_8::id());
    let simd_0339_active =
        agave_feature_set.is_active(&agave_feature_set::increase_cpi_account_info_limit::id());
    batch_processor.set_execution_cost(
        ComputeBudget::new_with_defaults(simd_0268_active, simd_0339_active).to_cost(),
    );
    register_builtins(&bank, &batch_processor);
    register_precompiles(&bank);
    batch_processor.fill_missing_sysvar_cache_entries(&bank);

    let versioned_tx: VersionedTransaction = bincode::deserialize(&fixture.transaction)?;
    let address_loader = SimpleAddressLoader::Enabled(LoadedAddresses {
        writable: fixture.alt_writable.clone(),
        readonly: fixture.alt_readonly.clone(),
    });
    let reserved = ReservedAccountKeys::new_all_activated().active;
    let sanitized = SanitizedTransaction::try_create(
        versioned_tx,
        solana_transaction::sanitized::MessageHash::Compute,
        None,
        address_loader,
        &reserved,
    )?;

    if log_instructions {
        print_instructions_after_sanitization(&sanitized);
    }

    let fee_details = replay_fee_details(fixture, &sanitized, &agave_feature_set);

    let env = TransactionProcessingEnvironment {
        blockhash: fixture.recent_blockhash,
        blockhash_lamports_per_signature: fixture.lamports_per_signature,
        epoch_total_stake: 0,
        feature_set,
        program_runtime_environments_for_execution: batch_processor.get_environments_for_epoch(0),
        program_runtime_environments_for_deployment: batch_processor.get_environments_for_epoch(0),
        rent: extract_rent(&fixture.sysvars),
    };
    let cfg = TransactionProcessingConfig {
        recording_config: ExecutionRecordingConfig {
            enable_log_recording: true,
            enable_return_data_recording: true,
            enable_cpi_recording: false,
            enable_transaction_balance_recording: false,
        },
        ..Default::default()
    };
    let check = vec![Ok(CheckedTransactionDetails::new(
        None,
        SVMTransactionExecutionAndFeeBudgetLimits {
            budget: svm_budget,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
            fee_details,
        },
    ))];

    let out = batch_processor.load_and_execute_sanitized_transactions(
        &bank,
        std::slice::from_ref(&sanitized),
        check,
        &env,
        &cfg,
    );

    Ok((sanitized, out.processing_results))
}

fn replay_fixture(
    fixture: &TransactionFixture,
    replace_programs: &[ProgramReplacement],
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if verbose {
        println!("\nbuilding SVM environment...");
    }
    let (sanitized, results) = execute_fixture(fixture, replace_programs, true)?;
    if verbose {
        println!("sanitizing transaction...");
        println!("executing...\n");
        print_outcome(fixture, &sanitized, &results);
    }
    Ok(())
}

fn print_fixture_summary(f: &TransactionFixture) {
    println!("\n--- fixture ---");
    println!("  schema_version  : {}", f.schema_version);
    println!("  slot            : {}", f.slot);
    println!(
        "  client_version  : {}",
        f.client_version()
            .map_or_else(|e| format!("<{e}>"), |v| v.to_string()),
    );
    println!("  enabled features: {}", f.enabled_features.len());
    println!("  pre-accounts    : {}", f.pre_accounts.len());
    println!("  post-accounts   : {}", f.post_accounts.len());
    println!("  loader-v3 progs : {}", f.programs.len());
    println!("  sysvars         : {}", f.sysvars.len());
    println!("  alt writable    : {}", f.alt_writable.len());
    println!("  alt readonly    : {}", f.alt_readonly.len());
    println!("  expected CUs    : {}", f.result.compute_units_consumed);
}

fn print_outcome(
    fix: &TransactionFixture,
    message: &SanitizedTransaction,
    results: &[solana_svm::transaction_processing_result::TransactionProcessingResult],
) {
    let result = results
        .first()
        .expect("expected exactly one processing result");

    let expected_status: Result<(), solana_transaction_error::TransactionError> =
        bincode::deserialize(&fix.result.status).unwrap_or(Err(
            solana_transaction_error::TransactionError::AccountNotFound,
        ));

    println!("--- replay outcome ---");
    match result {
        Ok(ProcessedTransaction::Executed(exec)) => {
            let exec = exec.as_ref();
            let actual_status = exec.execution_details.status.clone().map(|_| ());
            let actual_cus = exec.execution_details.executed_units;
            let logs = exec
                .execution_details
                .log_messages
                .clone()
                .unwrap_or_default();

            println!("  actual status   : {actual_status:?}");
            println!("  expected status : {expected_status:?}");
            print_match("  status          ", actual_status == expected_status);

            println!(
                "  actual CUs      : {actual_cus}\n  expected CUs    : {}",
                fix.result.compute_units_consumed,
            );
            print_match(
                "  CUs             ",
                actual_cus == fix.result.compute_units_consumed,
            );
            let (post_mismatches, synthetic_checked) = post_account_mismatches(fix, exec, message);
            print_match("  post-state      ", post_mismatches.is_empty());

            println!("\n  log messages ({}):", logs.len());
            for msg in &logs {
                println!("    {msg}");
            }

            print_return_data_diff(fix, exec);
            print_post_account_detail(fix, &post_mismatches, synthetic_checked);
        }
        Ok(ProcessedTransaction::FeesOnly(fee_only)) => {
            println!("  fees-only (load failed): {:?}", fee_only.load_error);
            println!("  expected status : {expected_status:?}");
        }
        Err(e) => {
            println!("  discarded: {e:?}");
            println!("  expected status : {expected_status:?}");
        }
    }
}

fn return_data_matches(fix: &TransactionFixture, exec: &ExecutedTransaction) -> bool {
    let exp_prog = fix.result.return_data_program;
    let exp_data: &[u8] = &fix.result.return_data;
    match &exec.execution_details.return_data {
        None => exp_data.is_empty() && exp_prog == Pubkey::default(),
        Some(TransactionReturnData { program_id, data }) => {
            program_id == &exp_prog && data.as_slice() == exp_data
        }
    }
}

fn print_return_data_diff(fix: &TransactionFixture, exec: &ExecutedTransaction) {
    println!("\n--- return data ---");
    println!("  expected program : {}", fix.result.return_data_program);
    println!("  expected data len: {}", fix.result.return_data.len(),);
    match &exec.execution_details.return_data {
        None => println!("  actual           : <none>"),
        Some(rd) => println!(
            "  actual program   : {}\n  actual data len  : {}",
            rd.program_id,
            rd.data.len(),
        ),
    }
    print_match("  return data      ", return_data_matches(fix, exec));
}

fn format_small_account_data(actual: &[u8], expected: &[u8]) -> String {
    const MAX_HEX_BYTES: usize = 96;
    let hex_actual: String = actual
        .iter()
        .take(MAX_HEX_BYTES)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let hex_expected: String = expected
        .iter()
        .take(MAX_HEX_BYTES)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let utf8_actual = String::from_utf8_lossy(actual);
    let utf8_expected = String::from_utf8_lossy(expected);
    format!(
        "actual_hex=[{hex_actual}] expected_hex=[{hex_expected}] | \
         actual_utf8_lossy={utf8_actual:?} expected_utf8_lossy={utf8_expected:?}"
    )
}

fn post_account_shared_matches(
    fa: &FixtureAccount,
    actual: &AccountSharedData,
) -> Result<(), String> {
    let expected_data = fa.data.inline_bytes().ok_or_else(|| {
        format!(
            "{}: fixture post_account has Hash blob (need RPC-resolved fixture)",
            fa.pubkey
        )
    })?;
    if actual.lamports() != fa.lamports {
        return Err(format!(
            "{}: lamports actual {} expected {}",
            fa.pubkey,
            actual.lamports(),
            fa.lamports
        ));
    }
    if *actual.owner() != fa.owner {
        return Err(format!(
            "{}: owner actual {} expected {}",
            fa.pubkey,
            actual.owner(),
            fa.owner
        ));
    }
    if !rent_epochs_equivalent(fa, actual.rent_epoch()) {
        return Err(format!(
            "{}: rent_epoch actual {} expected {}",
            fa.pubkey,
            actual.rent_epoch(),
            fa.rent_epoch
        ));
    }
    if actual.executable() != fa.is_executable() {
        return Err(format!(
            "{}: executable actual {} expected {}",
            fa.pubkey,
            actual.executable(),
            fa.is_executable()
        ));
    }
    if actual.data() != expected_data {
        let detail = format_small_account_data(actual.data(), expected_data);
        return Err(format!(
            "{}: data len actual {} expected {} | {detail}",
            fa.pubkey,
            actual.data().len(),
            expected_data.len(),
        ));
    }
    Ok(())
}

/// Post-state the bank commits after execution.
///
/// Successful txs: all writable changes in `loaded_transaction.accounts`.
/// Failed txs: writable changes roll back to pre-state; only the fee payer
/// (and nonce account when present) stay post-fee / post-nonce-advance via
/// [`RollbackAccounts`], matching penrose's `bank.get_account` post snapshot.
fn committed_post_accounts_for_failed_tx(
    fix: &TransactionFixture,
    rollback: &solana_svm::rollback_accounts::RollbackAccounts,
) -> HashMap<Pubkey, AccountSharedData> {
    let mut map: HashMap<Pubkey, AccountSharedData> = fix
        .pre_accounts
        .iter()
        .map(|fa| (fa.pubkey, fixture_account_to_shared(fa)))
        .collect();
    for (pubkey, account) in rollback {
        map.insert(*pubkey, account.clone());
    }
    map
}

fn post_account_mismatches(
    fix: &TransactionFixture,
    exec: &ExecutedTransaction,
    message: &SanitizedTransaction,
) -> (Vec<String>, usize) {
    if fix.post_accounts.is_empty() {
        return (Vec::new(), 0);
    }
    let loaded: HashMap<Pubkey, &AccountSharedData> = exec
        .loaded_transaction
        .accounts
        .iter()
        .map(|(k, v)| (*k, v))
        .collect();
    let failed_committed = exec.execution_details.status.is_err().then(|| {
        committed_post_accounts_for_failed_tx(fix, &exec.loaded_transaction.rollback_accounts)
    });
    let mut mismatches = Vec::new();
    let mut synthetic_checked = 0usize;
    for fa in &fix.post_accounts {
        if let Some(kind) = synthetic_accounts::classify(&fa.pubkey) {
            synthetic_checked += 1;
            match loaded.get(&fa.pubkey) {
                None => mismatches.push(format!(
                    "{}: pubkey not in loaded transaction account list after execution",
                    fa.pubkey
                )),
                Some(act) => {
                    if let Err(e) = synthetic_accounts::validate_post_account(kind, act, message) {
                        mismatches.push(e);
                    }
                }
            }
            continue;
        }

        let act = if let Some(ref committed) = failed_committed {
            committed.get(&fa.pubkey)
        } else {
            loaded.get(&fa.pubkey).copied()
        };
        match act {
            None => mismatches.push(format!(
                "{}: pubkey not in replay committed post-state",
                fa.pubkey
            )),
            Some(act) => {
                if let Err(e) = post_account_shared_matches(fa, act) {
                    mismatches.push(e);
                }
            }
        }
    }
    (mismatches, synthetic_checked)
}

fn print_post_account_detail(
    fix: &TransactionFixture,
    mismatches: &[String],
    synthetic_checked: usize,
) {
    println!("\n--- post-account state (fixture vs replay committed post-state) ---");
    if fix.post_accounts.is_empty() {
        println!("  (no post_accounts in fixture)");
        return;
    }

    if mismatches.is_empty() {
        if synthetic_checked > 0 {
            println!(
                "  all {} fixture post_account entries ({} synthetic): MATCH replay state",
                fix.post_accounts.len(),
                synthetic_checked,
            );
        } else {
            println!(
                "  all {} fixture post_account entries: MATCH replay state",
                fix.post_accounts.len()
            );
        }
    } else {
        for m in mismatches {
            println!("  MISMATCH: {m}");
        }
    }
}

fn print_match(label: &str, ok: bool) {
    println!("{label}: {}", if ok { "MATCH" } else { "MISMATCH" });
}

fn fixture_account_to_shared(fa: &FixtureAccount) -> AccountSharedData {
    AccountSharedData::from(Account {
        lamports: fa.lamports,
        data: fa.data.expect_inline().clone(),
        owner: fa.owner,
        executable: fa.is_executable(),
        rent_epoch: fa.rent_epoch,
    })
}

fn build_mock_bank(f: &TransactionFixture, feature_set: FeatureSet) -> MockBank {
    let bank = MockBank::new(feature_set);
    {
        let mut accounts = bank.accounts.write().unwrap();

        for fa in &f.pre_accounts {
            accounts.insert(fa.pubkey, fixture_account_to_shared(fa));
        }

        let rent = extract_rent(&f.sysvars);
        for sv in f.sysvars.iter() {
            let mut acct = AccountSharedData::default();
            acct.set_data_from_slice(&sv.data);
            acct.set_owner(solana_sdk_ids::sysvar::id());
            acct.set_lamports(rent.minimum_balance(sv.data.len()));
            acct.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);
            accounts.insert(sv.sysvar_id, acct);
        }

        for prog in &f.programs {
            let programdata = build_loader_v3_programdata_account(prog);
            accounts.insert(get_program_data_address(&prog.program_id), programdata);
        }
    }
    bank
}

fn build_loader_v3_programdata_account(prog: &FixtureProgramData) -> AccountSharedData {
    let bytes = prog.programdata.expect_inline();
    let mut acct = AccountSharedData::default();
    acct.set_owner(bpf_loader_upgradeable::id());
    acct.set_lamports(Rent::default().minimum_balance(bytes.len()));
    acct.set_data_from_slice(bytes);
    acct
}

fn extract_rent(sysvars: &[FixtureSysvar]) -> Rent {
    sysvars
        .iter()
        .find(|s| s.sysvar_id == solana_sdk_ids::sysvar::rent::ID)
        .and_then(|s| bincode::deserialize::<Rent>(&s.data).ok())
        .unwrap_or_default()
}

fn feature_sets_from_fixture(active: &[Pubkey]) -> (FeatureSet, SVMFeatureSet) {
    let active: AHashMap<Pubkey, u64> = active.iter().copied().map(|p| (p, 0u64)).collect();
    let inactive: AHashSet<Pubkey> = AHashSet::new();
    let agave = FeatureSet::new(active, inactive);
    let svm = agave.runtime_features();
    (agave, svm)
}

fn replay_fee_details(
    fixture: &TransactionFixture,
    sanitized: &SanitizedTransaction,
    agave_feature_set: &FeatureSet,
) -> FeeDetails {
    let signature_count = sanitized
        .num_transaction_signatures()
        .saturating_add(sanitized.num_ed25519_signatures())
        .saturating_add(sanitized.num_secp256k1_signatures())
        .saturating_add(sanitized.num_secp256r1_signatures());
    let sig_fee = signature_count.saturating_mul(fixture.lamports_per_signature);
    let prioritization_fee = process_compute_budget_instructions(
        SVMStaticMessage::program_instructions_iter(sanitized),
        agave_feature_set,
    )
    .unwrap_or_default()
    .get_prioritization_fee();
    FeeDetails::new(sig_fee, prioritization_fee)
}

fn rent_epochs_equivalent(fa: &FixtureAccount, actual: u64) -> bool {
    if actual == fa.rent_epoch {
        return true;
    }
    // Fixture snapshots from the validator bank often use u64::MAX for rent-exempt
    // accounts; replay may report 0 until load normalization, or the reverse when
    // an account becomes rent-exempt in the same transaction.
    let max = RENT_EXEMPT_RENT_EPOCH;
    (actual == 0 && fa.rent_epoch == max) || (actual == max && fa.rent_epoch == 0)
}

struct MockBank {
    accounts: RwLock<HashMap<Pubkey, AccountSharedData>>,
    feature_set: FeatureSet,
}

impl MockBank {
    fn new(feature_set: FeatureSet) -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
            feature_set,
        }
    }
}

impl InvokeContextCallback for MockBank {
    fn is_precompile(&self, program_id: &Pubkey) -> bool {
        is_precompile(program_id, |feature_id| self.feature_set.is_active(feature_id))
    }

    fn process_precompile(
        &self,
        program_id: &Pubkey,
        data: &[u8],
        instruction_datas: Vec<&[u8]>,
    ) -> Result<(), PrecompileError> {
        if let Some(precompile) = get_precompile(program_id, |feature_id| {
            self.feature_set.is_active(feature_id)
        }) {
            precompile.verify(data, &instruction_datas, &self.feature_set)
        } else {
            Err(PrecompileError::InvalidPublicKey)
        }
    }
}

impl TransactionProcessingCallback for MockBank {
    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<(AccountSharedData, u64)> {
        self.accounts
            .read()
            .unwrap()
            .get(pubkey)
            .cloned()
            .map(|a| (a, 0))
    }

    fn inspect_account(&self, _pubkey: &Pubkey, _state: AccountState, _writable: bool) {}
}

struct ReplayForkGraph;

impl ForkGraph for ReplayForkGraph {
    fn relationship(&self, a: u64, b: u64) -> BlockRelation {
        match a.cmp(&b) {
            Ordering::Less => BlockRelation::Ancestor,
            Ordering::Equal => BlockRelation::Equal,
            Ordering::Greater => BlockRelation::Descendant,
        }
    }
}

/// Mirror [`Bank::add_precompile`]: bogus executable native-loader accounts the SVM
/// loads then routes through [`InvokeContextCallback::process_precompile`].
fn register_precompiles(bank: &MockBank) {
    for precompile in get_precompiles() {
        if precompile
            .feature
            .is_none_or(|feature_id| bank.feature_set.is_active(&feature_id))
        {
            install_precompiled_account(bank, &precompile.program_id);
        }
    }
}

fn install_precompiled_account(bank: &MockBank, program_id: &Pubkey) {
    let mut accounts = bank.accounts.write().unwrap();
    if accounts
        .get(program_id)
        .is_some_and(|acct| acct.executable() && native_loader::check_id(acct.owner()))
    {
        return;
    }
    let mut acct = AccountSharedData::default();
    acct.set_owner(native_loader::id());
    acct.set_executable(true);
    acct.set_lamports(1);
    accounts.insert(*program_id, acct);
}

fn register_builtins(bank: &MockBank, processor: &TransactionBatchProcessor<ReplayForkGraph>) {
    install_builtin(
        bank,
        processor,
        solana_system_program::id(),
        "system_program",
        solana_system_program::system_processor::Entrypoint::vm,
    );
    install_builtin(
        bank,
        processor,
        compute_budget::id(),
        "compute_budget_program",
        solana_compute_budget_program::Entrypoint::vm,
    );
    install_builtin(
        bank,
        processor,
        bpf_loader_upgradeable::id(),
        "solana_bpf_loader_upgradeable_program",
        solana_bpf_loader_program::Entrypoint::vm,
    );
    install_builtin(
        bank,
        processor,
        bpf_loader::id(),
        "solana_bpf_loader_program",
        solana_bpf_loader_program::Entrypoint::vm,
    );
    install_builtin(
        bank,
        processor,
        bpf_loader_deprecated::id(),
        "solana_bpf_loader_deprecated_program",
        solana_bpf_loader_program::Entrypoint::vm,
    );
}

fn install_builtin(
    bank: &MockBank,
    processor: &TransactionBatchProcessor<ReplayForkGraph>,
    program_id: Pubkey,
    name: &'static str,
    register_fn: BuiltinFunctionWithContext,
) {
    let preserve_existing = bank
        .accounts
        .read()
        .unwrap()
        .get(&program_id)
        .is_some_and(|acct| native_loader::check_id(acct.owner()));

    if !preserve_existing {
        let mut acct = AccountSharedData::default();
        acct.set_owner(native_loader::id());
        acct.set_executable(true);
        acct.set_data_from_slice(name.as_bytes());
        acct.set_lamports(1);
        bank.accounts.write().unwrap().insert(program_id, acct);
    }

    processor.add_builtin(
        program_id,
        ProgramCacheEntry::new_builtin(0, name.len(), register_fn),
    );
}
