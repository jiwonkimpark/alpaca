use std::marker::PhantomData;
use ff::{Field, PrimeField};
use nova_snark::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::traits::circuit::TrivialCircuit;
use nova_snark::traits::Engine;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use crate::proofs::relation_nova::ivc::f_circuit::FCircuit;
use crate::proofs::relation_nova::ivc::ivc::IvcZ;

pub struct ZkSnarkIVC<E1, E2, S1, S2>
where
    E1: Engine<Base=<E2 as Engine>::Scalar>,
    E2: Engine<Base=<E1 as Engine>::Scalar>,
    S1: RelaxedR1CSSNARKTrait<E1>,
    S2: RelaxedR1CSSNARKTrait<E2>,
{
    _p1: PhantomData<E1>,
    _p2: PhantomData<E2>,
    _p3: PhantomData<S1>,
    _p4: PhantomData<S2>,
}

impl<E1, E2, S1, S2> ZkSnarkIVC<E1, E2, S1, S2>
where
    E1: Engine<Base=<E2 as Engine>::Scalar>,
    E2: Engine<Base=<E1 as Engine>::Scalar>,
    S1: RelaxedR1CSSNARKTrait<E1>,
    S2: RelaxedR1CSSNARKTrait<E2>,
    <E2 as Engine>::Scalar: PrimeField<Repr=[u8; 32]>,
{
    pub fn setup(pp: &PublicParams<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>) ->
    (
        ProverKey<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>, S1, S2>,
        VerifierKey<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>, S1, S2>
    ) {
        let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
        (pk, vk)
    }

    pub fn prove(
        pp: &PublicParams<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>,
        pk: &ProverKey<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>, S1, S2>,
        pi_sync: &RecursiveSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>,
    ) ->
        CompressedSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>, S1, S2>
    {
        let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(pp, pk, pi_sync);
        res.unwrap()
    }

    pub fn verify(
        vk: &VerifierKey<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>, S1, S2>,
        compressed_proof: &CompressedSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>, S1, S2>,
        num_steps: usize,
        z_0: IvcZ<E1::Scalar>,
    ) -> bool {
        let res = compressed_proof.verify(
            vk,
            num_steps,
            &[z_0.com_k_i, z_0.h_j, z_0.pk_id_x, z_0.pk_id_y, z_0.pk_sp_x, z_0.pk_sp_y],
            &[<E2 as Engine>::Scalar::ZERO]
        );
        res.is_ok()
    }
}

#[cfg(test)]
mod test {
    use ff::{Field, PrimeField};
    use nova_snark::provider::{PallasEngine, VestaEngine};
    use nova_snark::provider::ipa_pc::EvaluationEngine;
    use nova_snark::spartan::snark::RelaxedR1CSSNARK;
    use nova_snark::traits::circuit::TrivialCircuit;
    use nova_snark::traits::Engine;
    use pasta_curves::pallas;
    use rand_core::OsRng;
    use crate::blocklist::BlocklistingScheme;
    use crate::commitment::PoseidonCommitment;
    use crate::curve::{PallasCurve, PastaCurve, VestaCurve};
    use crate::proofs::relation_nova::ivc::f_circuit::{FCircuitW, FCircuit, FCircuitZ};
    use crate::proofs::relation_nova::ivc::ivc::{IvcW, Ivc, IvcZ};
    use crate::proofs::relation_nova::zksnark::ZkSnarkIVC;
    use crate::traits::blocklist::AnonymousBlocklistingScheme;
    use crate::traits::commitment::CommitmentScheme;

    #[test]
    fn test_prove_and_verify() {
        type E1 = PallasEngine;
        type E2 = VestaEngine;
        type EE1 = EvaluationEngine<E1>;
        type EE2 = EvaluationEngine<E2>;
        type S1 = RelaxedR1CSSNARK<E1, EE1>;
        type S2 = RelaxedR1CSSNARK<E2, EE2>;

        let scheme = BlocklistingScheme::<
            PallasCurve,
            VestaCurve,
            PallasEngine,
            VestaEngine,
            RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
            RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
        >::new();
        let (pp, pk_sp, pk_id, pk_r, pk_nova, sk_sp, sk_id, vk_r, vk_nova)
            = scheme.setup().unwrap();
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

        let t_1 = blocklist.get(1).unwrap();
        let t_0 = blocklist.get(0).unwrap();

        let r_1 = <E1 as Engine>::Scalar::random(csprng);

        let z_0 = FCircuitZ::<<E1 as Engine>::Scalar>::new::<VestaCurve>(com_k_b, t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        let w_0 = FCircuitW::<<E1 as Engine>::Scalar>::new(com_k_b, k_b, r_com_b, sign_start_r_x, sign_start_r_y, sign_start_b.s.to_repr(), None, None, None, 0, &cold_start_block_b, Some(t_1), Some(t_0), r_com_b, r_1);
        let primary_circuit = FCircuit::<<E1 as Engine>::Scalar>::new(z_0, w_0);

        // IvcNova setup is wrapped in Blocklisting scheme setup
        // let pp = IvcNova::<E1, E2, S1, S2>::setup(&primary_circuit, &TrivialCircuit::default());

        // ZkSnarkIvcNova setup is wrapped in Blocklisting scheme setup
        // let (pk, vk) = ZkSnarkIvcNova::<E1, E2, S1, S2>::setup(&pp);

        let z_0 = IvcZ { com_k_i: com_k_b, h_j: t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y };
        let aux_0: IvcW<PallasCurve, VestaCurve> = IvcW::new(
            &cred_b,
            None,
            Some(t_1),
            Some(t_0),
            r_com_b,
            r_1,
            0,
        );
        let mut pi_sync = Ivc::<E1, E2, S1, S2>::base_proof(&pp, z_0.clone(), aux_0);

        let t_2 = blocklist.get(2).unwrap();
        let r_2 = <E1 as Engine>::Scalar::random(csprng);
        let com_k_1 = PoseidonCommitment::<<E1 as Engine>::Scalar>::commit(&k_b, &r_1).unwrap();

        let z_1 = IvcZ { com_k_i: com_k_1, h_j: t_2.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y };
        let aux_1: IvcW<PallasCurve, VestaCurve> = IvcW::new(
            &cred_b,
            None,
            Some(t_2),
            Some(t_1),
            r_com_b,
            r_2,
            1,
        );
        let pi_sync_1 = Ivc::<E1, E2, S1, S2>::prove(&pp, z_1, aux_1, &mut pi_sync);

        let compressed_snark = ZkSnarkIVC::<E1, E2, S1, S2>::prove(&pp, &pk_nova, pi_sync_1);
        let res = ZkSnarkIVC::<E1, E2, S1, S2>::verify(&vk_nova, &compressed_snark, 1, z_0.clone());
        assert_eq!(res, true)
    }
}