use crate::errors::AnonymousBlocklistError;

pub trait CommitmentScheme {
    type CommitMessage;
    type Randomness;
    type Commitment;

    fn commit(message: &Self::CommitMessage, randomness: &Self::Randomness) -> Result<Self::Commitment, AnonymousBlocklistError>;

    fn open(revealed_msg: &Self::CommitMessage, commitment: &Self::Commitment, randomness: &Self::Randomness) -> Result<bool, AnonymousBlocklistError>;
}