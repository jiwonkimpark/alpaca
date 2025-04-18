use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AnonymousBlocklistError {
    #[error("InvalidCommitment")]
    InvalidCommitment,

    #[error("InvalidSignature")]
    InvalidSignature,

    #[error("InvalidHash")]
    InvalidHash,

    #[error("UnauthorizedUser")]
    UnauthorizedUser,

    #[error("InvalidStartingBlock")]
    InvalidStartingBlock,

    #[error("NotFoundException")]
    NotFoundException,

    #[error("InvalidParameter")]
    InvalidParameter,
}