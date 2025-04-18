use crate::errors::AnonymousBlocklistError;
use crate::util::DomainSeparator;

pub trait HashFunction {
    type Input;
    type Output;

    fn hash(msg: &Self::Input, domain_separator: DomainSeparator) -> Result<Self::Output, AnonymousBlocklistError>;
}