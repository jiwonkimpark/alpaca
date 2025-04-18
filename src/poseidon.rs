use bellpepper_core::boolean::{AllocatedBit, Boolean};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper_core::num::AllocatedNum;
use ff::{PrimeField, PrimeFieldBits};
use generic_array::typenum::U24;
use neptune::{Strength};
use neptune::circuit2::Elt;
use neptune::poseidon::PoseidonConstants;
use neptune::sponge::api::{IOPattern, SpongeAPI, SpongeOp};
use neptune::sponge::circuit::SpongeCircuit;
use neptune::sponge::vanilla::Mode::Simplex;
use neptune::sponge::vanilla::{Sponge, SpongeTrait};
use serde::{Deserialize, Serialize};
use crate::traits::ro::{RandomOracle, RandomOracleCircuit};
use crate::hash::poseidon::PoseidonHash;
use crate::traits::hash::HashFunction;
use crate::util::DomainSeparator;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PoseidonConstantsCircuit<F: PrimeField>(PoseidonConstants<F, U24>);

impl<F: PrimeField> Default for PoseidonConstantsCircuit<F> {
    fn default() -> Self {
        Self(Sponge::<F, U24>::api_constants(Strength::Standard))
    }
}

/// A Poseidon-based RO to use outside circuits
#[derive(Serialize, Deserialize)]
struct PoseidonRO<F>
    where
        F: PrimeField,
{
    state: Vec<F>,
    constants: PoseidonConstantsCircuit<F>,
    num_absorbs: usize,
    squeezed: bool,
}

impl<F> RandomOracle<F> for PoseidonRO<F>
    where
        F: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
{
    type Constants = PoseidonConstantsCircuit<F>;

    fn new(num_absorbs: usize) -> Self {
        Self {
            state: Vec::new(),
            constants: PoseidonConstantsCircuit::<F>::default(),
            num_absorbs,
            squeezed: false,
        }
    }

    /// Absorb a new number into the state of the oracle
    /// * `e` - the field input for the hash function
    /// This function pushes the field into the state.
    /// The real poseidon absorb and squeeze will be processed in squeeze function.
    fn absorb(&mut self, e: F) {
        assert!(!self.squeezed, "Cannot absorb after squeezing");
        self.state.push(e);
    }

    /// Compute a challenge by hashing the current state
    /// * `domain_separator` - the domain separator to distinguish the purpose of poseidon hash.
    /// This function uses SpongeAPI to absorb the state and squeeze into one field element.
    fn squeeze(&mut self, domain_separator: Option<u32>) -> F {
        assert!(!self.squeezed, "Cannot squeeze after squeezing");
        self.squeezed = true;

        let mut sponge = Sponge::new_with_constants(&self.constants.0, Simplex);
        let acc = &mut ();
        let parameter = IOPattern(vec![
            SpongeOp::Absorb(self.num_absorbs as u32),
            SpongeOp::Squeeze(1u32),
        ]);

        sponge.start(parameter, domain_separator, acc);
        assert_eq!(self.num_absorbs, self.state.len());
        SpongeAPI::absorb(&mut sponge, self.num_absorbs as u32, &self.state, acc);
        let squeezed = SpongeAPI::squeeze(&mut sponge, 1, acc);
        sponge.finish(acc).unwrap();

        return squeezed[0];
    }
}

pub fn poseidon_hash<F: PrimeField>(message: Vec<F>, domain_separator: u32) -> F {
    // let num_absorbs = message.len();
    // let mut ro: PoseidonRO<F> = PoseidonRO::new(num_absorbs);
    //
    // for m in message{
    //     ro.absorb(m);
    // }
    //
    // return ro.squeeze(Some(domain_separator));
    let digest = PoseidonHash::<F>::hash(&message, DomainSeparator::from(domain_separator)).unwrap();
    return digest
}

/// TODO: check if PoseidonROCircuit is needed -- the following code was copied from Nova
/// A Poseidon-based RO gadget to use inside the verifier circuit.
#[derive(Serialize, Deserialize)]
pub struct PoseidonROCircuit<Scalar: PrimeField> {
    state: Vec<AllocatedNum<Scalar>>,
    constants: PoseidonConstantsCircuit<Scalar>,
    num_absorbs: usize,
    squeezed: bool,
}

//TODO Update the Circuit Implementation??
impl<Scalar> RandomOracleCircuit<Scalar> for PoseidonROCircuit<Scalar>
    where
        Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
{
    type Constants = PoseidonConstantsCircuit<Scalar>;

    /// Initialize the internal state and set the poseidon constants
    fn new(constants: PoseidonConstantsCircuit<Scalar>, num_absorbs: usize) -> Self {
        Self {
            state: Vec::new(),
            constants,
            num_absorbs,
            squeezed: false,
        }
    }

    /// Absorb a new number into the state of the oracle
    fn absorb(&mut self, e: &AllocatedNum<Scalar>) {
        assert!(!self.squeezed, "Cannot absorb after squeezing");
        self.state.push(e.clone());
    }

    /// Compute a challenge by hashing the current state
    fn squeeze<CS: ConstraintSystem<Scalar>>(
        &mut self,
        mut cs: CS,
        domain_separator: Option<u32>,
    ) -> Result<Vec<AllocatedBit>, SynthesisError> {
        // check if we have squeezed already
        assert!(!self.squeezed, "Cannot squeeze again after squeezing");
        self.squeezed = true;
        let parameter = IOPattern(vec![
            SpongeOp::Absorb(self.num_absorbs as u32),
            SpongeOp::Squeeze(1u32),
        ]);
        let mut ns = cs.namespace(|| "ns");

        let hash = {
            let mut sponge = SpongeCircuit::new_with_constants(&self.constants.0, Simplex);
            let acc = &mut ns;
            assert_eq!(self.num_absorbs, self.state.len());

            sponge.start(parameter, domain_separator, acc);
            neptune::sponge::api::SpongeAPI::absorb(
                &mut sponge,
                self.num_absorbs as u32,
                &(0..self.state.len())
                    .map(|i| Elt::Allocated(self.state[i].clone()))
                    .collect::<Vec<Elt<Scalar>>>(),
                acc,
            );

            let output = neptune::sponge::api::SpongeAPI::squeeze(&mut sponge, 1, acc);
            sponge.finish(acc).unwrap();
            output
        };

        let hash = Elt::ensure_allocated(&hash[0], &mut ns.namespace(|| "ensure allocated"), true)?;

        // return the hash as a vector of bits, truncated
        Ok(
            hash
                .to_bits_le_strict(ns.namespace(|| "poseidon hash to boolean"))?
                .iter()
                .map(|boolean| match boolean {
                    Boolean::Is(ref x) => x.clone(),
                    _ => panic!("Wrong type of input. We should have never reached there"),
                })
                .collect::<Vec<AllocatedBit>>()
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use bellpepper::util_cs::witness_cs::WitnessCS;
    use bellpepper_core::boolean::AllocatedBit;
    use bellpepper_core::num::AllocatedNum;
    use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
    use ff::{Field, PrimeField, PrimeFieldBits};
    use nova_snark::provider::{PallasEngine, VestaEngine};
    use nova_snark::traits::{Engine};
    use crate::traits::ro::{RandomOracle, RandomOracleCircuit};
    use crate::poseidon::{PoseidonConstantsCircuit, PoseidonRO, PoseidonROCircuit};
    use crate::util::rand_field;

    /// A `ConstraintSystem` which calculates witness values for a concrete instance of an R1CS circuit.
    pub type SatisfyingAssignment<E> = WitnessCS<<E as Engine>::Base>;

    fn test_poseidon_ro_with<E: Engine>()
        where
            <<E as Engine>::Base as PrimeField>::Repr: std::fmt::Debug,
            <<E as Engine>::Scalar as PrimeField>::Repr: std::fmt::Debug,
            <<E as Engine>::Base as PrimeField>::Repr:
            PartialEq<<<E as Engine>::Base as PrimeField>::Repr>,
    {
        // Check that the number computed inside the circuit is equal to the number computed outside the circuit
        let constants = PoseidonConstantsCircuit::<E::Base>::default();
        let num_absorbs = 32;
        let mut ro: PoseidonRO<E::Base> = PoseidonRO::new(num_absorbs); //double check
        let mut ro_gadget: PoseidonROCircuit<E::Base> =
            PoseidonROCircuit::new(constants, num_absorbs);
        let mut cs = SatisfyingAssignment::<E>::new();
        for i in 0..num_absorbs {
            let num = rand_field::<E::Base>();
            ro.absorb(num);
            let num_gadget = AllocatedNum::alloc_infallible(cs.namespace(|| format!("data {i}")), || num);
            num_gadget
                .inputize(&mut cs.namespace(|| format!("input {i}")))
                .unwrap();
            ro_gadget.absorb(&num_gadget);
        }
        let num = ro.squeeze(None);
        let num2_bits = ro_gadget.squeeze(&mut cs, None).unwrap();
        let num2 = le_bits_to_num(&mut cs, &num2_bits).unwrap();
        assert_eq!(num.to_repr(), num2.get_value().unwrap().to_repr()); 
    }

    /// Gets as input the little indian representation of a number and spits out the number
    fn le_bits_to_num<Scalar, CS>(
        mut cs: CS,
        bits: &[AllocatedBit],
    ) -> Result<AllocatedNum<Scalar>, SynthesisError>
        where
            Scalar: PrimeField + PrimeFieldBits,
            CS: ConstraintSystem<Scalar>,
    {
        // We loop over the input bits and construct the constraint
        // and the field element that corresponds to the result
        let mut lc = LinearCombination::zero();
        let mut coeff = Scalar::ONE;
        let mut fe = Some(Scalar::ZERO);
        for bit in bits.iter() {
            lc = lc + (coeff, bit.get_variable());
            fe = bit.get_value().map(|val| {
                if val {
                    fe.unwrap() + coeff
                } else {
                    fe.unwrap()
                }
            });
            coeff = coeff.double();
        }
        let num = AllocatedNum::alloc(cs.namespace(|| "Field element"), || {
            fe.ok_or(SynthesisError::AssignmentMissing)
        })?;
        lc = lc - num.get_variable();
        cs.enforce(|| "compute number from bits", |lc| lc, |lc| lc, |_| lc);
        Ok(num)
    }

    #[test]
    fn test_poseidon_ro() {
        test_poseidon_ro_with::<PallasEngine>();
        test_poseidon_ro_with::<VestaEngine>();
    }
}