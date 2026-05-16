use thiserror::Error;

#[derive(Debug, Error)]
pub enum PenroseTypesError {
    #[error("wincode read error: {0}")]
    WincodeRead(#[from] wincode::ReadError),

    #[error("bincode error: {0}")]
    Bincode(#[from] bincode::Error),
}
