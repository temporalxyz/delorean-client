use wincode::{SchemaRead, SchemaWrite};

pub(crate) const BLOB_HASH_LEN: usize = 32;

#[derive(SchemaWrite, SchemaRead)]
pub enum FixtureBlob {
    Inline(Vec<u8>),
    Hash([u8; BLOB_HASH_LEN]),
}

impl FixtureBlob {
    #[inline]
    pub fn inline_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Inline(d) => Some(d.as_slice()),
            Self::Hash(_) => None,
        }
    }

    #[inline]
    pub fn hash(&self) -> Option<&[u8; BLOB_HASH_LEN]> {
        match self {
            Self::Inline(_) => None,
            Self::Hash(h) => Some(h),
        }
    }

    #[inline]
    pub fn expect_inline(&self) -> &Vec<u8> {
        match self {
            Self::Inline(d) => d,
            Self::Hash(_) => {
                panic!("FixtureBlob::expect_inline called on a Hash variant; resolve first")
            }
        }
    }
}
