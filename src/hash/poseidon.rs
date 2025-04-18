use std::marker::PhantomData;
use ff::PrimeField;
use crate::errors::AnonymousBlocklistError;
use crate::hash::sponge::Sponge;
use crate::traits::hash::HashFunction;
use crate::util::DomainSeparator;

pub struct PoseidonHash<F: PrimeField>
{
    _p: PhantomData<F>,
}

const RATE: usize = 8;

impl<F> HashFunction for PoseidonHash<F>
    where
        F: PrimeField
{
    type Input = Vec<F>;
    type Output = F;

    fn hash(msg: &Self::Input, domain_separator: DomainSeparator) -> Result<Self::Output, AnonymousBlocklistError> {
        let mut sponge = Sponge::new(8, 8, 57);
        let digest = sponge.run(msg.clone(), domain_separator);

        return Ok(digest)
    }
}
