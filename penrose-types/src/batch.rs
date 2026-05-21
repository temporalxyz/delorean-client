//! Batch wire format for `getTransactionFixtures`: shared blob table plus
//! fixtures that reference blobs by index instead of inlining duplicates.

use {
    crate::{
        blob::FixtureBlob,
        error::PenroseTypesError,
        fixture::{
            DefaultFixtureConfig, FIXTURE_ACCOUNT_FLAG_EXECUTABLE, FixtureAccount,
            FixtureProgramData, FixtureSysvar, TransactionFixture,
        },
        result::ExecutionResult,
    },
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    std::sync::Arc,
    wincode::{SchemaRead, containers::Vec as WincodeVec, len::BincodeLen},
};

/// Schema version for [`TransactionFixturesBatch`]. Bump on incompatible changes.
pub const BATCH_SCHEMA_VERSION: u32 = 0;

/// Index into [`TransactionFixturesBatch::blobs`].
pub type BlobIndex = u32;

/// Blob field shape on the batch RPC wire: small payloads stay inline,
/// spilled payloads point into the shared [`TransactionFixturesBatch::blobs`]
/// table.
#[derive(Clone, Debug, SchemaRead)]
pub enum FixtureBlobBatch {
    Inline(Vec<u8>),
    Shared(BlobIndex),
}

impl FixtureBlobBatch {
    #[inline]
    pub fn inline_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Inline(d) => Some(d.as_slice()),
            Self::Shared(_) => None,
        }
    }

    #[inline]
    pub fn shared_index(&self) -> Option<BlobIndex> {
        match self {
            Self::Inline(_) => None,
            Self::Shared(i) => Some(*i),
        }
    }
}

/// Account entry using [`FixtureBlobBatch`] on the `data` field.
#[derive(Clone, Debug, SchemaRead)]
pub struct FixtureAccountBatch {
    pub pubkey: Pubkey,
    pub owner: Pubkey,
    pub lamports: u64,
    pub rent_epoch: u64,
    pub flags: u8,
    pub data: FixtureBlobBatch,
}

impl FixtureAccountBatch {
    pub fn is_executable(&self) -> bool {
        self.flags & FIXTURE_ACCOUNT_FLAG_EXECUTABLE != 0
    }
}

#[derive(Clone, Debug, SchemaRead)]
pub struct FixtureProgramDataBatch {
    pub program_id: Pubkey,
    pub programdata: FixtureBlobBatch,
}

/// Fixture record on the batch wire (blob refs resolved to shared indices).
#[derive(Clone, Debug, SchemaRead)]
pub struct TransactionFixtureBatch {
    pub schema_version: u32,
    pub slot: u64,
    pub recent_blockhash: Hash,
    pub signature: Signature,
    #[wincode(with = "WincodeVec<u8, BincodeLen>")]
    pub client_version: Vec<u8>,
    #[wincode(with = "WincodeVec<Pubkey, BincodeLen>")]
    pub enabled_features: Vec<Pubkey>,
    pub lamports_per_signature: u64,
    #[wincode(with = "WincodeVec<u8, BincodeLen>")]
    pub transaction: Vec<u8>,
    #[wincode(with = "WincodeVec<Pubkey, BincodeLen>")]
    pub alt_writable: Vec<Pubkey>,
    #[wincode(with = "WincodeVec<Pubkey, BincodeLen>")]
    pub alt_readonly: Vec<Pubkey>,
    #[wincode(with = "WincodeVec<FixtureAccountBatch, BincodeLen>")]
    pub pre_accounts: Vec<FixtureAccountBatch>,
    #[wincode(with = "WincodeVec<FixtureProgramDataBatch, BincodeLen>")]
    pub programs: Vec<FixtureProgramDataBatch>,
    pub sysvars: Arc<Vec<FixtureSysvar>>,
    pub result: ExecutionResult,
    #[wincode(with = "WincodeVec<FixtureAccountBatch, BincodeLen>")]
    pub post_accounts: Vec<FixtureAccountBatch>,
}

/// Response body for `getTransactionFixtures`: deduplicated blob payloads plus
/// one optional fixture per requested signature (same order as the request).
#[derive(Clone, Debug, SchemaRead)]
pub struct TransactionFixturesBatch {
    pub batch_schema_version: u32,
    #[wincode(with = "WincodeVec<WincodeVec<u8, BincodeLen>, BincodeLen>")]
    pub blobs: Vec<Vec<u8>>,
    #[wincode(with = "WincodeVec<Option<TransactionFixtureBatch>, BincodeLen>")]
    pub fixtures: Vec<Option<TransactionFixtureBatch>>,
}

#[inline]
fn wincode_config() -> DefaultFixtureConfig {
    wincode::config::Configuration::default().disable_preallocation_size_limit()
}

impl TransactionFixturesBatch {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PenroseTypesError> {
        Ok(wincode::config::deserialize(bytes, wincode_config())?)
    }
}

fn resolve_blob_batch(blob: FixtureBlobBatch, blobs: &[Vec<u8>]) -> FixtureBlob {
    match blob {
        FixtureBlobBatch::Inline(bytes) => FixtureBlob::Inline(bytes),
        FixtureBlobBatch::Shared(index) => {
            let bytes = blobs
                .get(index as usize)
                .expect("penrose-server must return consistent batch blob indices");
            FixtureBlob::Inline(bytes.clone())
        }
    }
}

impl TransactionFixtureBatch {
    /// Expand shared blob indices into a fully-inlined fixture for replay.
    ///
    /// Panics if `blobs` does not match shared indices (server bug or corrupt payload).
    pub fn into_inlined(self, blobs: &[Vec<u8>]) -> TransactionFixture {
        let map_account = |a: FixtureAccountBatch| FixtureAccount {
            pubkey: a.pubkey,
            owner: a.owner,
            lamports: a.lamports,
            rent_epoch: a.rent_epoch,
            flags: a.flags,
            data: resolve_blob_batch(a.data, blobs),
        };
        let map_program = |p: FixtureProgramDataBatch| FixtureProgramData {
            program_id: p.program_id,
            programdata: resolve_blob_batch(p.programdata, blobs),
        };

        TransactionFixture {
            schema_version: self.schema_version,
            slot: self.slot,
            recent_blockhash: self.recent_blockhash,
            signature: self.signature,
            client_version: self.client_version,
            enabled_features: self.enabled_features,
            lamports_per_signature: self.lamports_per_signature,
            transaction: self.transaction,
            alt_writable: self.alt_writable,
            alt_readonly: self.alt_readonly,
            pre_accounts: self.pre_accounts.into_iter().map(map_account).collect(),
            programs: self.programs.into_iter().map(map_program).collect(),
            sysvars: self.sysvars,
            result: self.result,
            post_accounts: self.post_accounts.into_iter().map(map_account).collect(),
        }
    }
}
