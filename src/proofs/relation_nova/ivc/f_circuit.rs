use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use bellpepper_core::num::AllocatedNum;
use circ::ir::term::Value;
use circ::target::r1cs::spartan_opt::r1cs_values;
use ff::{Field, PrimeField, PrimeFieldBits};
use fxhash::FxHashMap;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::Engine;
use serde::{Deserialize, Serialize};
use crate::blocklist::Block;
use crate::commitment::PoseidonCommitment;
use crate::curve::{PastaCurve};
use crate::poseidon::poseidon_hash;
use crate::proofs::relation_nova::ivc::r1cs_adapter::{IVC_R1CS, R1CSAdapter};
use crate::proofs::utils::{zok_input_map, In, InputValue};
use crate::traits::blocklist::AnonymousBlocklistingScheme;
use crate::traits::commitment::CommitmentScheme;
use crate::traits::signature::SignatureScheme;
use crate::util::DomainSeparator::HASH;
use crate::util::root_abs_path;

#[derive(Clone)]
pub struct FCircuitW<F: PrimeField> {
    com_k: F,
    k: F,
    r_com: F,
    sign_start_r_x: F,
    sign_start_r_y: F,
    sign_start_s: [u8; 32],
    sign_ban_over_r_x: Option<F>,
    sign_ban_over_r_y: Option<F>,
    sign_ban_over_s: Option<[u8; 32]>,
    j: usize,
    b_start: Block<F, F>,
    b_j: Option<Block<F, F>>,
    b_j_minus_1: Option<Block<F, F>>,
    r_i: F,
    r_i_plus_1: F,
}

impl <F: PrimeField> FCircuitW<F> {
    fn b_j_or_default(&self) -> Block<F, F> {
        self.clone().b_j.unwrap_or_default()
    }

    fn b_j_minus_1_or_default(&self) -> Block<F, F> {
        self.clone().b_j_minus_1.unwrap_or_default()
    }
}

impl<F: PrimeField> FCircuitW<F> {
    pub fn new(
        com_k: F,
        k: F,
        r_com: F,
        sign_start_r_x: F,
        sign_start_r_y: F,
        sign_start_s: [u8; 32],
        sign_ban_over_r_x: Option<F>,
        sign_ban_over_r_y: Option<F>,
        sign_ban_over_s: Option<[u8; 32]>,
        j: usize,
        b_start: &Block<F, F>,
        b_j: Option<&Block<F, F>>,
        b_j_minus_1: Option<&Block<F, F>>,
        r_i: F,
        r_i_plus_1: F
    ) -> Self {
        Self {
            com_k,
            k,
            r_com,
            sign_start_r_x,
            sign_start_r_y,
            sign_start_s,
            sign_ban_over_r_x,
            sign_ban_over_r_y,
            sign_ban_over_s,
            j,
            b_start: b_start.clone(),
            b_j: if b_j.is_some() { Some(b_j.unwrap().clone()) } else { None },
            b_j_minus_1: if b_j_minus_1.is_some() { Some(b_j_minus_1.unwrap().clone()) } else { None },
            r_i,
            r_i_plus_1,
        }
    }
}

#[derive(Clone)]
pub struct FCircuitZ<F: PrimeField> {
    com_k_i: F,
    h_j: F,
    pk_id_x: F,
    pk_id_y: F,
    pk_sp_x: F,
    pk_sp_y: F,
}

impl<F: PrimeField> FCircuitZ<F> {
    pub fn new<C: PastaCurve>(com_k_j: F, h_i: F, pk_id_x: F, pk_id_y: F, pk_sp_x: F, pk_sp_y: F) -> FCircuitZ<F> {
        FCircuitZ { com_k_i: com_k_j, h_j: h_i, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y }
    }
}

#[derive(Clone)]
pub struct FCircuit<F: PrimeField> {
    z_i: FCircuitZ<F>,
    w_i: FCircuitW<F>,
}

impl<F: PrimeField> FCircuit<F> {
    pub fn new(z_i: FCircuitZ<F>, w_i: FCircuitW<F>) -> Self {
        Self { z_i, w_i }
    }
}

impl<F: PrimeField> StepCircuit<F> for FCircuit<F> {
    fn arity(&self) -> usize {
        6
    }

    fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, z_in: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(z_in.len(), self.arity());
        let com_k_i = z_in[0].clone();
        let h_j = z_in[1].clone();
        let pk_id_x = z_in[2].clone();
        let pk_id_y = z_in[3].clone();
        let pk_sp_x = z_in[4].clone();
        let pk_sp_y = z_in[5].clone();

        if com_k_i.get_value().is_some() {
            assert_eq!(com_k_i.get_value().unwrap(), self.z_i.com_k_i)
        }

        if h_j.get_value().is_some() {
            assert_eq!(h_j.get_value().unwrap(), self.z_i.h_j)
        }

        let linear_combinations = self.linear_combinations(cs);
        for (i, (a, b, c)) in linear_combinations.into_iter().enumerate() {
            cs.enforce(|| format!("con_{i}"), |_| a, |_| b, |_| c);
        }

        let z_out = {
            let com_k_i_plus_1 = {
                let committed = PoseidonCommitment::<F>::commit(&self.w_i.k, &self.w_i.r_i_plus_1).unwrap();
                AllocatedNum::alloc(cs.namespace(|| format!("com_k_{}", self.w_i.j + 1)), || {
                    Ok(committed)
                }).unwrap()
            };

            let h_j_plus_1 = if self.w_i.b_j.is_some() {
                let block_j = self.w_i.b_j.clone().unwrap();
                let hash_message = [block_j.nonce, block_j.message_hash, block_j.tag, block_j.h].to_vec();
                let hash_of_b_j = poseidon_hash::<F>(hash_message, HASH.value());
                AllocatedNum::alloc(cs.namespace(|| format!("h_{}", block_j.i + 1)), || {
                    Ok(hash_of_b_j)
                }).unwrap()
            } else {
                AllocatedNum::alloc(cs.namespace(|| format!("h_{}", self.w_i.b_j.clone().unwrap().i +  1)), || {
                    Ok(self.z_i.h_j)
                }).unwrap()
            };

            vec![com_k_i_plus_1, h_j_plus_1, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y]
        };

        Ok(z_out)
    }
}

impl<F: PrimeField> FCircuit<F> {
    fn linear_combinations<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<(LinearCombination<F>, LinearCombination<F>, LinearCombination<F>)> {
        let precompute_path = root_abs_path() + "/IVC_PRECOMPUTE";
        let pin_map = self.pin_map();
        let values = r1cs_values(&*precompute_path, IVC_R1CS.vars.len(), &pin_map).expect("failed to get r1cs values from circ");

        let linear_combinations = R1CSAdapter::<F>::linear_combinations(&values, cs, "relations".parse().unwrap());

        linear_combinations
    }

    fn pin_map(&self) -> FxHashMap<String, Value> {
        let b_j_or_default = self.w_i.b_j_or_default();
        let b_j_minus_1_or_default = self.w_i.b_j_minus_1_or_default();
        let sign_ban_over_s = self.w_i.sign_ban_over_s.unwrap_or([0u8; 32]);

        let inputs: Vec<In<F>> = vec![
            ("com_k", InputValue::Field(self.w_i.com_k)),
            ("k", InputValue::Field(self.w_i.k)),
            ("r_com", InputValue::Field(self.w_i.r_com)),
            ("pk_id_x", InputValue::Field(self.z_i.pk_id_x)),
            ("pk_id_y", InputValue::Field(self.z_i.pk_id_y)),
            ("sign_start_R_x", InputValue::Field(self.w_i.sign_start_r_x)),
            ("sign_start_R_y", InputValue::Field(self.w_i.sign_start_r_y)),
            ("sign_start_s", InputValue::Bytes(self.w_i.sign_start_s.as_ref())),
            ("b_start_nonce", InputValue::Field(self.w_i.b_start.nonce)),
            ("b_start_tag", InputValue::Field(self.w_i.b_start.tag)),
            ("b_start_h", InputValue::Field(self.w_i.b_start.h)),
            ("h_j", InputValue::Field(self.z_i.h_j)),
            ("b_j_minus_1_nonce", InputValue::Field(b_j_minus_1_or_default.nonce)),
            ("b_j_minus_1_message_hash", InputValue::Field(b_j_minus_1_or_default.message_hash)),
            ("b_j_minus_1_tag", InputValue::Field(b_j_minus_1_or_default.tag)),
            ("b_j_minus_1_h", InputValue::Field(b_j_minus_1_or_default.h)),
            ("com_k_i", InputValue::Field(self.z_i.com_k_i)),
            ("r_i", InputValue::Field(self.w_i.r_i)),
            ("b_j_nonce", InputValue::Field(b_j_or_default.nonce)),
            ("b_j_message_hash", InputValue::Field(b_j_or_default.message_hash)),
            ("b_j_tag", InputValue::Field(b_j_or_default.tag)),
            ("b_j_h", InputValue::Field(b_j_or_default.h)),
            ("pk_sp_x", InputValue::Field(self.z_i.pk_sp_x)),
            ("pk_sp_y", InputValue::Field(self.z_i.pk_sp_y)),
            ("sign_ban_over_r_x", InputValue::Field(self.w_i.sign_ban_over_r_x.unwrap_or(F::ZERO))),
            ("sign_ban_over_r_y", InputValue::Field(self.w_i.sign_ban_over_r_y.unwrap_or(F::ZERO))),
            ("sign_ban_over_s", InputValue::Bytes(&sign_ban_over_s)),
        ]
            .into_iter()
            .map(|(k, v)| In::new(k, v))
            .collect();

        let pin_map = zok_input_map(inputs);

        pin_map
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use bellpepper_core::ConstraintSystem;
    use bellpepper_core::num::AllocatedNum;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use ff::{Field, PrimeField};
    use nova_snark::provider::{PallasEngine, VestaEngine};
    use nova_snark::provider::ipa_pc::EvaluationEngine;
    use nova_snark::{CompressedSNARK, PublicParams, RecursiveSNARK};
    use nova_snark::spartan::snark::RelaxedR1CSSNARK;
    use nova_snark::traits::circuit::{StepCircuit, TrivialCircuit};
    use nova_snark::traits::Engine;
    use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
    use pasta_curves::pallas;
    use rand_core::OsRng;
    use crate::blocklist::BlocklistingScheme;
    use crate::commitment::PoseidonCommitment;
    use crate::curve::{PallasCurve, PastaCurve, VestaCurve};
    use crate::proofs::relation_nova::ivc::f_circuit::{FCircuitW, FCircuit, FCircuitZ};
    use crate::traits::blocklist::AnonymousBlocklistingScheme;
    use crate::traits::commitment::CommitmentScheme;
    use crate::util::{hex_str, hex_string_from};

    #[test]
    fn test_get_linear_combinations() {
        let mut cs: TestConstraintSystem<<PallasCurve as PastaCurve>::Scalar> = TestConstraintSystem::new();

        let scheme = BlocklistingScheme::<
            PallasCurve,
            VestaCurve,
            PallasEngine,
            VestaEngine,
            RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
            RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
        >::new();;
        let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark)
            = scheme.setup().unwrap();

        let mut blocklist = scheme.initialize_blocklist().unwrap();

        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        let mut csprng = OsRng;
        let msg1 = <pallas::Scalar as Field>::random(csprng);
        let token1 = scheme.extract_token(&cred, &msg1).unwrap();

        // add to blocklist
        blocklist = scheme.add_token_to_blocklist(&token1, &mut blocklist).unwrap().clone();
        let t_i = blocklist.last().unwrap();
        let t_i_minus_1 = blocklist.get(blocklist.len() - 2).unwrap();
        // r_j_plus_1
        let r_j_plus_1 = <pallas::Scalar as Field>::random(csprng);

        let (pk_id_x, pk_id_y) = VestaCurve::to_affine(&pk_id);
        let (pk_sp_x, pk_sp_y) = VestaCurve::to_affine(&pk_sp);
        let (sign_start_r_x, sign_start_r_y) = VestaCurve::to_affine(&sign_start.R);
        let sign_start_s_converted = {
            let repr = sign_start.s.to_repr();
            <PallasCurve as PastaCurve>::Scalar::from_repr(repr).unwrap()
        };

        let w = FCircuitW::<<PallasCurve as PastaCurve>::Scalar>::new(com_k, k, r_com, sign_start_r_x, sign_start_r_y, sign_start.s.to_repr(), None, None, None, 0, &cold_start_block, Some(t_i), Some(t_i_minus_1), r_com, r_j_plus_1);
        let z = FCircuitZ::<<PallasCurve as PastaCurve>::Scalar>::new::<VestaCurve>(com_k, t_i.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        let f_circuit = FCircuit::<<PallasCurve as PastaCurve>::Scalar>::new(z, w);

        let linear_combinations = f_circuit.linear_combinations(&mut cs);
    }

    #[test]
    fn test_synthesize() {
        let mut cs = TestConstraintSystem::new();

        let scheme = BlocklistingScheme::<
            PallasCurve,
            VestaCurve,
            PallasEngine,
            VestaEngine,
            RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
            RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
        >::new();
        let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark)
            = scheme.setup().unwrap();

        let mut blocklist = scheme.initialize_blocklist().unwrap();

        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        let mut csprng = OsRng;
        let msg1 = <pallas::Scalar as Field>::random(csprng);
        let token1 = scheme.extract_token(&cred, &msg1).unwrap();

        // add to blocklist
        blocklist = scheme.add_token_to_blocklist(&token1, &mut blocklist).unwrap().clone();
        let t_i = blocklist.last().unwrap();
        let t_i_minus_1 = blocklist.get(blocklist.len() - 2).unwrap();

        let (pk_id_x, pk_id_y) = VestaCurve::to_affine(&pk_id);
        let (pk_sp_x, pk_sp_y) = VestaCurve::to_affine(&pk_sp);
        let (sign_start_r_x, sign_start_r_y) = VestaCurve::to_affine(&sign_start.R);
        let sign_start_s_converted = {
            let repr = sign_start.s.to_repr();
            <PallasCurve as PastaCurve>::Scalar::from_repr(repr).unwrap()
        };

        // r_j_plus_1
        let r_j_plus_1 = <pallas::Scalar as Field>::random(csprng);

        let w = FCircuitW::<<PallasCurve as PastaCurve>::Scalar>::new(com_k, k, r_com, sign_start_r_x, sign_start_r_y, sign_start.s.to_repr(), None, None, None, 0, &cold_start_block, Some(t_i), Some(t_i_minus_1), r_com, r_j_plus_1);
        let z = FCircuitZ::<<PallasCurve as PastaCurve>::Scalar>::new::<VestaCurve>(com_k, t_i.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        let f_circuit = FCircuit::<<PallasCurve as PastaCurve>::Scalar>::new(z, w);

        // z_0 = (com_k, h_i)
        let z_0 = {
            let com_k_j = AllocatedNum::alloc(cs.namespace(|| format!("com_k_{}", 0)), || {
                Ok(com_k)
            }).unwrap();
            let h_i = AllocatedNum::alloc(cs.namespace(|| format!("h_{}", t_i.i)), || {
                Ok(t_i.h)
            }).unwrap();
            &[com_k_j, h_i]
        };

        let result = f_circuit.synthesize(&mut cs, z_0);

        assert!(result.err().is_none());
    }

    #[test]
    fn test_circuit() {
        // make environment for test
        // generate 3 blocks by credA
        // cred B register for t_start = t_1
        println!("Making blocklist environment for test...");
        let mut now = Instant::now();

        let scheme = BlocklistingScheme::<
            PallasCurve,
            VestaCurve,
            PallasEngine,
            VestaEngine,
            RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
            RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
        >::new();

        let now2 = Instant::now();
        println!("Setup...");
        let (pp, pk_sp, pk_id, pk_r, pk_nova, sk_sp, sk_id, vk_r, vk_nova)
            = scheme.setup().unwrap();
        let elapsed2 = now2.elapsed();
        println!("Elapsed for setup: {:.2?}", elapsed2);


        let (pk_id_x, pk_id_y) = VestaCurve::to_affine(&pk_id);
        let (pk_sp_x, pk_sp_y) = VestaCurve::to_affine(&pk_sp);

        let mut blocklist = scheme.initialize_blocklist().unwrap();

        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred_a = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        let mut csprng = OsRng;
        let msg1 = <pallas::Scalar as Field>::random(csprng);
        let token1 = scheme.extract_token(&cred_a, &msg1).unwrap();
        blocklist = scheme.add_token_to_blocklist(&token1, &mut blocklist).unwrap().clone();

        let cred_b_cold_start_block = blocklist.last().unwrap().clone(); // index = 1
        let (k_b, r_com_b, com_k_b) =
            scheme.register_user1().unwrap();
        let (cold_start_block_b, sign_start_b) =
            scheme.register_idp(sk_id.clone(), com_k_b.clone(), blocklist.clone()).unwrap();
        let cred_b = scheme.register_user2(k_b, r_com_b, &com_k_b, &cold_start_block_b, sign_start_b.clone()).unwrap();
        let (sign_start_r_x, sign_start_r_y) = VestaCurve::to_affine(&sign_start_b.R);

        let msg2 = <pallas::Scalar as Field>::random(csprng);
        let token2 = scheme.extract_token(&cred_a, &msg2).unwrap();
        blocklist = scheme.add_token_to_blocklist(&token2, &mut blocklist).unwrap().clone();

        let msg3 = <pallas::Scalar as Field>::random(csprng);
        let token3 = scheme.extract_token(&cred_a, &msg3).unwrap();
        blocklist = scheme.add_token_to_blocklist(&token3, &mut blocklist).unwrap().clone();

        let mut elapsed = now.elapsed();
        println!("Elapsed for making blocklisting environment: {:.2?}", elapsed);

        type E1 = PallasEngine;
        type E2 = VestaEngine;
        type EE1 = EvaluationEngine<E1>;
        type EE2 = EvaluationEngine<E2>;
        type S1 = RelaxedR1CSSNARK<E1, EE1>;
        type S2 = RelaxedR1CSSNARK<E2, EE2>;

        let cs: TestConstraintSystem<<E1 as Engine>::Scalar> = TestConstraintSystem::new();

        println!("Generating a new circuit...");
        now = Instant::now();
        let num_steps = 1;
        let mut primary_circuits: Vec<FCircuit<<E1 as Engine>::Scalar>> = Vec::new();
        let t_1 = blocklist.get(1).unwrap();
        let t_0 = blocklist.get(0).unwrap();

        let r_1 = <E1 as Engine>::Scalar::random(csprng);

        let z_0 = FCircuitZ::<<E1 as Engine>::Scalar>::new::<VestaCurve>(com_k_b, t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        let w_0 = FCircuitW::<<E1 as Engine>::Scalar>::new(com_k_b, k_b, r_com_b, sign_start_r_x, sign_start_r_y, sign_start_b.s.to_repr(), None, None, None, 0, &cold_start_block_b, Some(t_1), Some(t_0), r_com_b, r_1);
        primary_circuits.push(FCircuit::<<E1 as Engine>::Scalar>::new(z_0, w_0));

        elapsed = now.elapsed();
        println!("Elapsed for generating a circuit: {:.2?}", elapsed);

        // let t_2 = blocklist.get(2).unwrap();
        // let r_2 = <E1 as Engine>::Scalar::random(csprng);
        //
        // let com_k_1 = PoseidonCommitment::<<E1 as Engine>::Scalar>::commit(&k_b, &r_1).unwrap();
        //
        // let z_1 = FCircuitZ::<<E1 as Engine>::Scalar>::new::<VestaCurve>(com_k_1, t_2.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        // let w_1 = FCircuitAux::<<E1 as Engine>::Scalar>::new(com_k_b, k_b, r_com_b, sign_start_r_x, sign_start_r_y, sign_start_b.s.to_repr(), None, None, None, 1, &cold_start_block_b, t_2, Some(t_1), r_1, r_2);
        //
        // primary_circuits.push(FCircuit::<<E1 as Engine>::Scalar>::new(z_1, w_1));

        // let circuit1 = primary_circuits[0].clone();
        let circuit2 = TrivialCircuit::default();
        // let ck_hint1 = &*S1::ck_floor();
        // let ck_hint2 = &*S2::ck_floor();
        //
        // now = Instant::now();
        //
        // let pp = PublicParams::setup(&circuit1, &circuit2, ck_hint1, ck_hint2).unwrap();

        // let mut elapsed = now.elapsed();
        // println!("Elapsed for public params setup: {:.2?}", elapsed);

        // println!(
        //     "Number of constraints per step (primary circuit): {}",
        //     pp.num_constraints().0
        // );
        // println!(
        //     "Number of constraints per step (secondary circuit): {}",
        //     pp.num_constraints().1
        // );
        //
        // println!(
        //     "Number of variables per step (primary circuit): {}",
        //     pp.num_variables().0
        // );
        // println!(
        //     "Number of variables per step (secondary circuit): {}",
        //     pp.num_variables().1
        // );

        type C1 = FCircuit<<E1 as Engine>::Scalar>;
        type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

        println!("Generating a RecursiveSNARK...");
        now = Instant::now();

        let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> =
            RecursiveSNARK::<E1, E2, C1, C2>::new(
                &pp,
                &primary_circuits[0],
                &circuit2,
                &[com_k_b, t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y],
                &[<E2 as Engine>::Scalar::zero()],
            )
                .unwrap();

        let mut elapsed = now.elapsed();
        println!("Elapsed for generating a recursive proofs: {:.2?}", elapsed);

        for (i, primary_circuit) in primary_circuits.iter().enumerate() {
            now = Instant::now();

            let res = recursive_snark.prove_step(&pp, primary_circuit, &circuit2);
            if !res.is_ok() {
                println!("{:?}", res.clone().err());
            }
            assert!(res.is_ok());

            let mut elapsed = now.elapsed();
            println!("Elapsed for a prove step: {:.2?}", elapsed);
        }
        println!("RecursiveSNARK::prove for {} steps", num_steps);

        // verify the recursive SNARK
        println!("Verifying a RecursiveSNARK...");

        now = Instant::now();

        let res = recursive_snark.verify(
            &pp,
            num_steps,
            &[com_k_b, t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y],
            &[<E2 as Engine>::Scalar::zero()],
        );
        println!("RecursiveSNARK::verify: {:?}", res.is_ok(), );
        assert!(res.is_ok());

        let mut elapsed = now.elapsed();
        println!("Elapsed for verifying: {:.2?}", elapsed);

        // Compressed SNARK

        // Don't need to run (already generated from blocklisting setup)
        // println!("Generating a CompressedSNARK using Spartan ...");
        // let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();

        let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk_nova, &recursive_snark);
        println!(
            "CompressedSNARK::prove: {:?}",
            res.is_ok()
        );
        assert!(res.is_ok());
        let compressed_snark = res.unwrap();

        // verify the compressed SNARK
        println!("Verifying a CompressedSNARK...");
        let res = compressed_snark.verify(&vk_nova, num_steps, &[com_k_b, t_1.h], &[<E2 as Engine>::Scalar::zero()]);
        println!(
            "CompressedSNARK::verify: {:?}",
            res.is_ok(),
        );
        assert!(res.is_ok());
    }
}