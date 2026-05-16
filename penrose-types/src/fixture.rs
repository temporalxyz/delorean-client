use {
    crate::{blob::FixtureBlob, error::PenroseTypesError, result::ExecutionResult},
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    std::sync::Arc,
    wincode::{SchemaRead, SchemaWrite, containers::Vec as WincodeVec, len::BincodeLen},
};

pub(crate) type DefaultFixtureConfig =
    wincode::config::Configuration<true, { wincode::config::PREALLOCATION_SIZE_LIMIT_DISABLED }>;

#[inline]
fn wincode_config() -> DefaultFixtureConfig {
    wincode::config::Configuration::default().disable_preallocation_size_limit()
}

pub(crate) const FIXTURE_ACCOUNT_FLAG_EXECUTABLE: u8 = 1 << 0;

#[derive(SchemaWrite, SchemaRead)]
pub struct TransactionFixture {
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

    #[wincode(with = "WincodeVec<FixtureAccount, BincodeLen>")]
    pub pre_accounts: Vec<FixtureAccount>,

    #[wincode(with = "WincodeVec<FixtureProgramData, BincodeLen>")]
    pub programs: Vec<FixtureProgramData>,

    pub sysvars: Arc<Vec<FixtureSysvar>>,

    pub result: ExecutionResult,

    #[wincode(with = "WincodeVec<FixtureAccount, BincodeLen>")]
    pub post_accounts: Vec<FixtureAccount>,
}

#[derive(SchemaWrite, SchemaRead)]
pub struct FixtureAccount {
    pub pubkey: Pubkey,
    pub owner: Pubkey,
    pub lamports: u64,
    pub rent_epoch: u64,
    pub flags: u8,
    pub data: FixtureBlob,
}

impl FixtureAccount {
    pub fn is_executable(&self) -> bool {
        self.flags & FIXTURE_ACCOUNT_FLAG_EXECUTABLE != 0
    }
}

#[derive(SchemaWrite, SchemaRead)]
pub struct FixtureProgramData {
    pub program_id: Pubkey,
    pub programdata: FixtureBlob,
}

#[derive(SchemaWrite, SchemaRead)]
pub struct FixtureSysvar {
    pub sysvar_id: Pubkey,
    #[wincode(with = "WincodeVec<u8, BincodeLen>")]
    pub data: Vec<u8>,
}

impl TransactionFixture {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PenroseTypesError> {
        Ok(wincode::config::deserialize(bytes, wincode_config())?)
    }

    pub fn client_version(&self) -> Result<solana_version::Version, PenroseTypesError> {
        Ok(bincode::deserialize(&self.client_version)?)
    }
}
