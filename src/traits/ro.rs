use bellpepper_core::boolean::AllocatedBit;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_core::num::AllocatedNum;
use ff::PrimeField;
use serde::{Deserialize, Serialize};

pub trait RandomOracle<F: PrimeField> {
    /// A type representing constants/parameters associated with the hash function
    type Constants: Default + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;

    /// Initializes the hash function
    fn new(num_absorbs: usize) -> Self;

    /// Adds a scalar to the internal state
    fn absorb(&mut self, e: F);

    /// Returns a challenge of `num_bits` by hashing the internal state
    fn squeeze(&mut self, domain_seperator: Option<u32>) -> F;
}

pub trait RandomOracleCircuit<Base: PrimeField> {
    /// the vanilla alter ego of this trait - this constrains it to use the same constants
    // type NativeRO<T: PrimeField>: RandomOracle<Base, T, Constants=Self::Constants>;

    /// A type representing constants/parameters associated with the hash function on this Base field
    type Constants: Default + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;

    /// Initializes the hash function
    fn new(constants: Self::Constants, num_absorbs: usize) -> Self;

    /// Adds a scalar to the internal state
    fn absorb(&mut self, e: &AllocatedNum<Base>);

    /// Returns a challenge of `num_bits` by hashing the internal state
    fn squeeze<CS: ConstraintSystem<Base>>(
        &mut self,
        cs: CS,
        domain_separator: Option<u32>,
    ) -> Result<Vec<AllocatedBit>, SynthesisError>;
}