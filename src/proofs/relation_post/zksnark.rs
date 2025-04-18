use std::io::{Read};
use std::marker::PhantomData;
use circ::ir::term::{Value};
use circ::target::r1cs::{ProverData, VerifierData};
use circ::target::r1cs::spartan_opt::{prove, verify};
use ff::{Field, PrimeField, PrimeFieldBits};
use fxhash::FxHashMap;
use libspartan::{Instance, NIZKGens};
use serde::{Deserialize, Serialize};
use crate::blocklist::{AuthToken, Block};
use crate::curve::PastaCurve;
use crate::errors::AnonymousBlocklistError;
use crate::signature::SchnorrSignature;
use crate::proofs::utils::{zok_input_map, In, InputValue};

pub struct ZkSnarkPost<C1: PastaCurve, C2: PastaCurve> {
    _p1: PhantomData<C1>,
    _p2: PhantomData<C2>,
}

const MODULAR: &str = "28948022309329048855892746252171976963363056481941647379679742748393362948097";

impl<C1: PastaCurve, C2: PastaCurve<Base=C1::Scalar, Scalar=C1::Base>> ZkSnarkPost<C1, C2> {
    pub(crate) fn prove(
        token: &AuthToken<C1::Scalar, C1::Scalar>,
        pk_id: C2::Point,
        com_k_prime: C1::Scalar,
        k: C1::Scalar,
        r_prime: C1::Scalar,
        sign_start: &SchnorrSignature<C2>,
        com_k: C1::Scalar,
        b_start: &Block<C1::Scalar, C1::Scalar>,
        r_com: C1::Scalar,
        prover_data: &ProverData,
        gens: &NIZKGens,
        inst: &Instance,
    ) -> Result<libspartan::NIZK, AnonymousBlocklistError> {
        let pin_map = Self::pin_map(token, pk_id, com_k_prime, k, r_prime, sign_start.clone(), com_k, b_start.clone(), r_com);
        let proof = prove(prover_data, &pin_map, gens, inst).expect("failed to get spartan proof from circ");

        Ok(proof)
    }

    pub(crate) fn verify(
        token: &AuthToken<C1::Scalar, C1::Scalar>,
        pk_id: C2::Point,
        com_k_prime: C1::Scalar,
        gens: &NIZKGens,
        inst: &Instance,
        proof: &libspartan::NIZK,
        verifier_data: &VerifierData,
    ) -> Result<bool, AnonymousBlocklistError> {
        let vin_map = Self::vin_map(token.clone(), pk_id, com_k_prime);
        let result = verify(verifier_data, &vin_map, gens, inst, proof.clone());

        Ok(result.is_ok())
    }

    fn pin_map(
        token: &AuthToken<C1::Scalar, C1::Scalar>,
        pk_id: C2::Point,
        com_k_prime: C1::Scalar,
        k: C1::Scalar,
        r_prime: C1::Scalar,
        sign_start: SchnorrSignature<C2>,
        com_k: C1::Scalar,
        b_start: Block<C1::Scalar, C1::Scalar>,
        r_com: C1::Scalar,
    ) -> FxHashMap<String, Value> {
        let (pk_id_x, pk_id_y): (C1::Scalar, C1::Scalar) = C2::to_affine(&pk_id);
        let (sign_start_x, sign_start_y): (C1::Scalar, C1::Scalar) = C2::to_affine(&sign_start.R);

        let scalar_inputs: Vec<In<C1::Scalar>> = vec![
            ("tag", InputValue::Field(token.tag)),
            ("nonce", InputValue::Field(token.nonce)),
            ("message_hash", InputValue::Field(token.message_hash)),
            ("pk_id_x", InputValue::Field(pk_id_x)),
            ("pk_id_y", InputValue::Field(pk_id_y)),
            ("com_k_prime", InputValue::Field(com_k_prime)),
            ("k", InputValue::Field(k)),
            ("r_prime", InputValue::Field(r_prime)),
            ("sign_start_R_x", InputValue::Field(sign_start_x)),
            ("sign_start_R_y", InputValue::Field(sign_start_y)),
            ("com_k", InputValue::Field(com_k)),
            ("b_start_nonce", InputValue::Field(b_start.nonce)),
            ("b_start_tag", InputValue::Field(b_start.tag)),
            ("b_start_h", InputValue::Field(b_start.h)),
            ("r_com", InputValue::Field(r_com)),
        ]
            .into_iter()
            .map(|(k, v)| In::new(k, v))
            .collect();

        let mut pin_map = zok_input_map(scalar_inputs);

        let base_inputs: Vec<In<C1::Base>> = vec![
            ("sign_start_s", InputValue::Field(sign_start.s)),
        ]
            .into_iter()
            .map(|(k, v)| In::new(k, v))
            .collect();

        pin_map.extend(zok_input_map(base_inputs));

        pin_map
    }

    fn vin_map(
        token: AuthToken<C1::Scalar, C1::Scalar>,
        pk_id: C2::Point,
        com_k_prime: C1::Scalar,
    ) -> FxHashMap<String, Value>
    {
        let (pk_id_x, pk_id_y): (C1::Scalar, C1::Scalar) = C2::to_affine(&pk_id);
        let expect_result: C1::Scalar = C1::Scalar::ZERO;

        let inputs: Vec<In<C1::Scalar>> = vec![
            ("tag", InputValue::Field(token.tag)),
            ("nonce", InputValue::Field(token.nonce)),
            ("message_hash", InputValue::Field(token.message_hash)),
            ("pk_id_x", InputValue::Field(pk_id_x)),
            ("pk_id_y", InputValue::Field(pk_id_y)),
            ("com_k_prime", InputValue::Field(com_k_prime)),
            ("return", InputValue::Field(expect_result)),
        ]
            .into_iter()
            .map(|(k, v)| In::new(k, v))
            .collect();

        let vin_map = zok_input_map(inputs);

        vin_map
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;
    use ff::{Field};
    use nova_snark::provider::{PallasEngine, VestaEngine};
    use nova_snark::provider::ipa_pc::EvaluationEngine;
    use nova_snark::spartan::snark::RelaxedR1CSSNARK;
    use pasta_curves::{pallas};
    use crate::blocklist::{BlocklistingScheme};
    use crate::commitment::PoseidonCommitment;
    use crate::curve::{PallasCurve, PastaCurve, VestaCurve};
    use crate::traits::blocklist::AnonymousBlocklistingScheme;
    use crate::traits::commitment::CommitmentScheme;
    use crate::util::{hex_str, rand_field};

    #[test]
    fn test_prove_and_verify() {
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

        let blocklist = scheme.initialize_blocklist().unwrap();

        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token = scheme.extract_token(&cred, &msg1).unwrap();

        let r_prime = rand_field::<<PallasCurve as PastaCurve>::Scalar>();
        let com_k_prime = PoseidonCommitment::<<PallasCurve as PastaCurve>::Scalar>::commit(&k, &r_prime).unwrap();

        // let proof = RelationR::<PallasCurve, VestaCurve>::prove(&token, pk_id, com_k_prime, k, r_prime, &sign_start, com_k, &cold_start_block, r_com).unwrap();
        // let verify_result = RelationR::<PallasCurve, VestaCurve>::verify(&token, pk_id, com_k_prime, com_k, &proof).unwrap();
        // assert!(verify_result)
    }
}