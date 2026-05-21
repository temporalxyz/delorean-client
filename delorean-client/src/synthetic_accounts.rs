//! Accounts the SVM constructs at transaction load time and never persists in
//! the bank.
//!
//! Penrose captures every tx account key via `bank.get_account()`. For these
//! pubkeys that lookup returns `None`, so fixtures store a default-empty
//! placeholder (owner `11111111111111111111111111111111`, zero lamports, empty
//! data). Replay reconstructs the real account in
//! [`solana_svm::account_loader`]. Post-state checks must compare replay output
//! against the synthesized form, not fixture bytes.
//!
//! To add another synthetic account:
//! 1. Add a [`SyntheticAccountKind`] variant.
//! 2. Extend [`classify`].
//! 3. Implement validation in [`validate_post_account`] (typically by mirroring
//!    the corresponding SVM loader logic).

use {
    solana_account::{Account, AccountSharedData, ReadableAccount},
    solana_instruction::{BorrowedAccountMeta, BorrowedInstruction},
    solana_instructions_sysvar::construct_instructions_data,
    solana_pubkey::Pubkey,
    solana_sdk_ids::sysvar::{self, instructions},
    solana_svm_transaction::svm_message::SVMMessage,
    solana_transaction::sanitized::SanitizedTransaction,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyntheticAccountKind {
    InstructionsSysvar,
}

/// Classify `pubkey` as a synthetic account, if applicable.
pub fn classify(pubkey: &Pubkey) -> Option<SyntheticAccountKind> {
    if instructions::check_id(pubkey) {
        return Some(SyntheticAccountKind::InstructionsSysvar);
    }
    None
}

/// Validate replay-loaded post-state for a synthetic account.
pub fn validate_post_account(
    kind: SyntheticAccountKind,
    actual: &AccountSharedData,
    message: &SanitizedTransaction,
) -> Result<(), String> {
    match kind {
        SyntheticAccountKind::InstructionsSysvar => {
            validate_instructions_sysvar(actual, message)
        }
    }
}

fn validate_instructions_sysvar(
    actual: &AccountSharedData,
    message: &SanitizedTransaction,
) -> Result<(), String> {
    let expected = construct_instructions_account(message);
    let pubkey = instructions::id();
    compare_shared_account_metadata(pubkey, actual, &expected)?;

    let expected_data = expected.data();
    let actual_data = actual.data();
    if actual_data.len() != expected_data.len() {
        return Err(format!(
            "{pubkey}: data len actual {} expected {}",
            actual_data.len(),
            expected_data.len(),
        ));
    }

    // The runtime rewrites the trailing u16 current-instruction index as
    // execution proceeds; the serialized instruction block prefix is fixed at
    // load time. See `instructions::store_current_index_checked`.
    const CURRENT_INDEX_LEN: usize = 2;
    if expected_data.len() < CURRENT_INDEX_LEN {
        return Err(format!(
            "{pubkey}: data too short for current-instruction index (len {})",
            expected_data.len(),
        ));
    }
    let prefix_len = expected_data.len() - CURRENT_INDEX_LEN;
    if actual_data[..prefix_len] != expected_data[..prefix_len] {
        return Err(format!(
            "{pubkey}: instruction payload mismatch (len {prefix_len})",
        ));
    }
    Ok(())
}

/// Mirror [`solana_svm::account_loader::construct_instructions_account`].
fn construct_instructions_account(message: &impl SVMMessage) -> AccountSharedData {
    let account_keys = message.account_keys();
    let mut decompiled_instructions = Vec::with_capacity(message.num_instructions());
    for (program_id, instruction) in message.program_instructions_iter() {
        let accounts = instruction
            .accounts
            .iter()
            .map(|account_index| {
                let account_index = usize::from(*account_index);
                BorrowedAccountMeta {
                    is_signer: message.is_signer(account_index),
                    is_writable: message.is_writable(account_index),
                    pubkey: account_keys.get(account_index).unwrap(),
                }
            })
            .collect();

        decompiled_instructions.push(BorrowedInstruction {
            accounts,
            data: instruction.data,
            program_id,
        });
    }

    AccountSharedData::from(Account {
        data: construct_instructions_data(&decompiled_instructions),
        owner: sysvar::id(),
        ..Account::default()
    })
}

fn compare_shared_account_metadata(
    pubkey: Pubkey,
    actual: &AccountSharedData,
    expected: &AccountSharedData,
) -> Result<(), String> {
    if actual.lamports() != expected.lamports() {
        return Err(format!(
            "{pubkey}: lamports actual {} expected {}",
            actual.lamports(),
            expected.lamports(),
        ));
    }
    if actual.owner() != expected.owner() {
        return Err(format!(
            "{pubkey}: owner actual {} expected {}",
            actual.owner(),
            expected.owner(),
        ));
    }
    if actual.rent_epoch() != expected.rent_epoch() {
        return Err(format!(
            "{pubkey}: rent_epoch actual {} expected {}",
            actual.rent_epoch(),
            expected.rent_epoch(),
        ));
    }
    if actual.executable() != expected.executable() {
        return Err(format!(
            "{pubkey}: executable actual {} expected {}",
            actual.executable(),
            expected.executable(),
        ));
    }
    Ok(())
}
