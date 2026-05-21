#![cfg(feature = "agave-unstable-api")]

#[path = "../../../../precompiles/src/ed25519.rs"]
mod ed25519;
#[path = "../../../../precompiles/src/secp256k1.rs"]
mod secp256k1;
#[path = "../../../../precompiles/src/secp256r1.rs"]
mod secp256r1;

use {
    agave_feature_set::FeatureSet, solana_message::compiled_instruction::CompiledInstruction,
    solana_precompile_error::PrecompileError, solana_pubkey::Pubkey, std::sync::LazyLock,
};

/// All precompiled programs must implement the `Verify` function
pub type Verify = fn(&[u8], &[&[u8]], &FeatureSet) -> std::result::Result<(), PrecompileError>;

/// Information on a precompiled program
pub struct Precompile {
    pub program_id: Pubkey,
    pub feature: Option<Pubkey>,
    pub verify_fn: Verify,
}

impl Precompile {
    pub fn new(program_id: Pubkey, feature: Option<Pubkey>, verify_fn: Verify) -> Self {
        Precompile {
            program_id,
            feature,
            verify_fn,
        }
    }

    pub fn check_id<F>(&self, program_id: &Pubkey, is_enabled: F) -> bool
    where
        F: Fn(&Pubkey) -> bool,
    {
        self.feature
            .is_none_or(|ref feature_id| is_enabled(feature_id))
            && self.program_id == *program_id
    }

    pub fn verify(
        &self,
        data: &[u8],
        instruction_datas: &[&[u8]],
        feature_set: &FeatureSet,
    ) -> std::result::Result<(), PrecompileError> {
        (self.verify_fn)(data, instruction_datas, feature_set)
    }
}

static PRECOMPILES: LazyLock<Vec<Precompile>> = LazyLock::new(|| {
    vec![
        Precompile::new(
            solana_sdk_ids::secp256k1_program::id(),
            None,
            secp256k1::verify,
        ),
        Precompile::new(
            solana_sdk_ids::ed25519_program::id(),
            None,
            ed25519::verify,
        ),
        Precompile::new(
            solana_sdk_ids::secp256r1_program::id(),
            None,
            secp256r1::verify,
        ),
    ]
});

pub fn is_precompile<F>(program_id: &Pubkey, is_enabled: F) -> bool
where
    F: Fn(&Pubkey) -> bool,
{
    PRECOMPILES
        .iter()
        .any(|precompile| precompile.check_id(program_id, |feature_id| is_enabled(feature_id)))
}

pub fn get_precompile<F>(program_id: &Pubkey, is_enabled: F) -> Option<&Precompile>
where
    F: Fn(&Pubkey) -> bool,
{
    PRECOMPILES
        .iter()
        .find(|precompile| precompile.check_id(program_id, |feature_id| is_enabled(feature_id)))
}

pub fn get_precompiles<'a>() -> &'a [Precompile] {
    &PRECOMPILES
}

pub fn verify_if_precompile(
    program_id: &Pubkey,
    precompile_instruction: &CompiledInstruction,
    all_instructions: &[CompiledInstruction],
    feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    for precompile in PRECOMPILES.iter() {
        if precompile.check_id(program_id, |feature_id| feature_set.is_active(feature_id)) {
            let instruction_datas: Vec<_> = all_instructions
                .iter()
                .map(|instruction| instruction.data.as_ref())
                .collect();
            return precompile.verify(
                &precompile_instruction.data,
                &instruction_datas,
                feature_set,
            );
        }
    }
    Ok(())
}
