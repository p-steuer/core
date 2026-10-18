//! Errors. Messages never contain secrets, so they may be logged.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the passphrase is wrong")]
    WrongPassphrase,
    #[error("the recovery key doesn't belong to this vault")]
    WrongRecoveryKey,
    #[error("the recovery key has a typo")]
    RecoveryKeyTypo,
    #[error("this isn't a recovery key")]
    RecoveryKeyInvalid,
    #[error("the passphrase is too short")]
    PassphraseTooShort,
    #[error("the passphrase is too long")]
    PassphraseTooLong,
    #[error("the passphrase is too easy to guess")]
    PassphraseTooWeak,
    #[error("a vault already exists here")]
    VaultExists,
    #[error("there is no vault here")]
    NoVault,
    #[error("not found")]
    NotFound,
    #[error("the vault is already open")]
    InUse,
    #[error("the vault is locked")]
    Locked,
    #[error("the vault can only be read because it is damaged")]
    ReadOnly,
    #[error("damaged data: {0}")]
    Damaged(&'static str),
    #[error("made by a newer version of the app: {0}")]
    Unsupported(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("storage error: {0}")]
    Io(String),
    #[error("no secure random numbers available")]
    Randomness,
    #[error("not enough memory")]
    OutOfMemory,
    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
