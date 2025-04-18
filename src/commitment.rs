use std::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use serde::{Deserialize, Serialize};
use crate::traits::commitment::CommitmentScheme;
use crate::errors::AnonymousBlocklistError;
use crate::poseidon::poseidon_hash;
use crate::util::DomainSeparator;

pub struct PoseidonCommitment<F: PrimeField> {
    _p: PhantomData<F>
}

impl<F: PrimeField> CommitmentScheme for PoseidonCommitment<F> {
    type CommitMessage = F;
    type Randomness = F;
    type Commitment = F;

    fn commit(message: &Self::CommitMessage, randomness: &Self::Randomness) -> Result<Self::Commitment, AnonymousBlocklistError> {
        let mut messages = Vec::new();
        messages.push(*message);
        messages.push(*randomness);

        let com = poseidon_hash::<F>(messages, DomainSeparator::COMMITMENT.value());

        Ok(com)
    }

    fn open(revealed_msg: &Self::CommitMessage, commitment: &Self::Commitment, randomness: &Self::Randomness) -> Result<bool, AnonymousBlocklistError> {
        let generated_commitment = Self::commit(revealed_msg, randomness).unwrap();
        if generated_commitment.eq(commitment) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::commitment::CommitmentScheme;
    use crate::commitment::PoseidonCommitment;
    use crate::curve::{PallasCurve, PastaCurve, VestaCurve};
    use crate::util::rand_field;


    fn test_poseidon_commitment_with<C: PastaCurve>() {
        let msg = rand_field::<C::Base>();
        let r = rand_field::<C::Base>();

        let com = PoseidonCommitment::<C::Base>::commit(&msg, &r).unwrap();

        let open_result = PoseidonCommitment::<C::Base>::open(&msg, &com, &r).unwrap();
        assert!(open_result)
    }

    #[test]
    fn test_poseidon_commitment() {
        test_poseidon_commitment_with::<PallasCurve>();
        test_poseidon_commitment_with::<VestaCurve>();
    }
}
