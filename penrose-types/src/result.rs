use {
    solana_pubkey::Pubkey,
    wincode::{SchemaRead, SchemaWrite, containers::Vec as WincodeVec, len::BincodeLen},
};

#[derive(SchemaWrite, SchemaRead)]
pub struct ExecutionResult {
    #[wincode(with = "WincodeVec<u8, BincodeLen>")]
    pub status: Vec<u8>,

    pub compute_units_consumed: u64,

    pub return_data_program: Pubkey,
    #[wincode(with = "WincodeVec<u8, BincodeLen>")]
    pub return_data: Vec<u8>,
}
