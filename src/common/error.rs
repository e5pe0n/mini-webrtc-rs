use thiserror::Error;

#[derive(Debug, Error)]
pub enum MiniWebrtcRsError {
    #[error("out of index; pos={pos:?}, len={len:?}.")]
    BufferOutOfIndexError { pos: usize, len: usize },
    #[error("invalid {enum_name:?}; `{value:?}` is not a variant.")]
    InvalidEnumVariantError { enum_name: String, value: String },
    #[error("not implemented; {message:?}")]
    NotImplementedError { message: String },
}
