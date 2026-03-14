use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("out of index; pos={pos:?}, len={len:?}.")]
    BufferOutOfIndexError { pos: usize, len: usize },
}
