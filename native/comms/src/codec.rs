pub trait CodecExt<'a>: Sized {
    type Error;
    fn serialize(self) -> Result<Vec<u8>, Self::Error>;
    fn deserialize(ser: &'a [u8]) -> Result<Self, Self::Error>;
}

pub mod magic {
    pub const MAGIC: &[u8; 2] = b"\xFA\xCE";
}

pub mod key {
    use std::env;

    use super::err;

    const KEYREF: &str = "AEADKEY";

    pub fn get() -> Result<Vec<u8>, err::CodecError> {
        match env::var(KEYREF) {
            Ok(key) => Ok(key.into_bytes()),
            Err(e) => Err(err::CodecError::InvalidKey(e)),
        }
    }
}

pub mod err {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum CodecError {
        #[error("{el} is corrupted; seq: {seq}")]
        Corrupted { el: String, seq: usize },
        #[error("incomplete packet")]
        Incomplete,
        #[error("invalid magic")]
        InvalidMagic,
        #[error("failed to retrieve key")]
        InvalidKey(#[from] std::env::VarError),
        #[error("unexpected issue during aead encryption")]
        Encryption,
        #[error("unexpected issue during aead decryption")]
        Decryption,
    }
}
