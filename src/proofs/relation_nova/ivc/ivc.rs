use std::marker::PhantomData;
use ff::{Field, PrimeField, PrimeFieldBits};
use nova_snark::{PublicParams, RecursiveSNARK};
use nova_snark::traits::circuit::TrivialCircuit;
use nova_snark::traits::Engine;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use serde::{Deserialize, Serialize};
use crate::blocklist::{Block, Cred};
use crate::curve::PastaCurve;
use crate::signature::SchnorrSignature;
use crate::proofs::relation_nova::ivc::f_circuit::{FCircuitW, FCircuit, FCircuitZ};

#[derive(Clone)]
pub struct IvcZ<F: PrimeField> {
    pub(crate) com_k_i: F,
    pub(crate) h_j: F,
    pub(crate) pk_id_x: F,
    pub(crate) pk_id_y: F,
    pub(crate) pk_sp_x: F,
    pub(crate) pk_sp_y: F,
}

impl<F: PrimeField> IvcZ<F> {
    pub fn new<C: PastaCurve>(com_k_i: F, h_j: F, pk_id: &C::Point, pk_sp: &C::Point) -> Self
    where
        C: PastaCurve<Base=F>,
    {
        let (pk_id_x, pk_id_y) = C::to_affine(pk_id);
        let (pk_sp_x, pk_sp_y) = C::to_affine(pk_sp);
        Self {
            com_k_i,
            h_j,
            pk_id_x,
            pk_id_y,
            pk_sp_x,
            pk_sp_y,
        }
    }
}

#[derive(Clone)]
pub struct IvcW<C1, C2>
where
    C1: PastaCurve,
    C2: PastaCurve<Base=C1::Scalar, Scalar=C1::Base>,
{
    cred: Cred<C1::Scalar, Block<C1::Scalar, C1::Scalar>, C1::Scalar, C1::Scalar, SchnorrSignature<C2>>,
    sign_ban_over: Option<SchnorrSignature<C2>>,
    b_j: Option<Block<C1::Scalar, C1::Scalar>>,
    b_j_minus_1: Option<Block<C1::Scalar, C1::Scalar>>,
    r_i: C1::Scalar,
    r_i_plus_1: C1::Scalar,
    i: usize,
}

impl<C1, C2> IvcW<C1, C2>
where
    C1: PastaCurve,
    C2: PastaCurve<Base=C1::Scalar, Scalar=C1::Base>,
{
    pub fn new(
        cred: &Cred<C1::Scalar, Block<C1::Scalar, C1::Scalar>, C1::Scalar, C1::Scalar, SchnorrSignature<C2>>,
        sign_ban_over: Option<&SchnorrSignature<C2>>,
        b_i: Option<&Block<C1::Scalar, C1::Scalar>>,
        b_i_minus_1: Option<&Block<C1::Scalar, C1::Scalar>>,
        r_j: C1::Scalar,
        r_j_plus_1: C1::Scalar,
        j: usize,
    ) -> Self {
        Self {
            cred: cred.clone(),
            sign_ban_over: if sign_ban_over.is_some() { Some(sign_ban_over.unwrap().clone()) } else { None },
            b_j: if b_i.is_some() { Some(b_i.unwrap().clone()) } else { None },
            b_j_minus_1: if b_i_minus_1.is_some() { Some(b_i_minus_1.unwrap().clone()) } else { None },
            r_i: r_j,
            r_i_plus_1: r_j_plus_1,
            i: j
        }
    }
}

pub struct Ivc<E1, E2, S1, S2>
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

impl<E1, E2, S1, S2> Ivc<E1, E2, S1, S2>
where
    E1: Engine<Base=<E2 as Engine>::Scalar>,
    E2: Engine<Base=<E1 as Engine>::Scalar>,
    S1: RelaxedR1CSSNARKTrait<E1>,
    S2: RelaxedR1CSSNARKTrait<E2>,
    <E2 as Engine>::Scalar: PrimeField<Repr=[u8; 32]>,
{
    pub fn setup(
        primary_circuit: &FCircuit<E1::Scalar>,
        secondary_circuit: &TrivialCircuit<E2::Scalar>,
    ) -> PublicParams<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>
    {
        let ck_hint1 = &*S1::ck_floor();
        let ck_hint2 = &*S2::ck_floor();
        let pp = PublicParams::setup(primary_circuit, secondary_circuit, ck_hint1, ck_hint2).unwrap();

        pp
    }

    pub fn base_proof<C1: PastaCurve, C2: PastaCurve<Base=C1::Scalar, Scalar=C1::Base>>(
        pp: &PublicParams<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>,
        z_0: IvcZ<E1::Scalar>,
        w_0: IvcW<C1, C2>,
    ) -> RecursiveSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>
    where
        C1: PastaCurve<Base=E1::Base, Scalar=E1::Scalar>,
        C2: PastaCurve<Base=E2::Base, Scalar=E2::Scalar>,
    {
        let f_z = FCircuitZ::<E1::Scalar>::new::<C2>(z_0.com_k_i, z_0.h_j, z_0.pk_id_x, z_0.pk_id_y, z_0.pk_sp_x, z_0.pk_sp_y);
        let f_w = Self::f_w_from(w_0);
        let f_circuit = FCircuit::<<E1 as Engine>::Scalar>::new(f_z, f_w);
        let secondary_circuit = TrivialCircuit::<<E2 as Engine>::Scalar>::default();

        let mut recursive_snark: RecursiveSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>> =
            RecursiveSNARK::<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>::new(
                pp,
                &f_circuit,
                &secondary_circuit,
                &[z_0.com_k_i, z_0.h_j, z_0.pk_id_x, z_0.pk_id_y, z_0.pk_sp_x, z_0.pk_sp_y],
                &[<E2 as Engine>::Scalar::ZERO],
            ).unwrap();

        recursive_snark
    }

    fn f_w_from<C1: PastaCurve, C2: PastaCurve<Base=C1::Scalar, Scalar=C1::Base>>(w_i: IvcW<C1, C2>) -> FCircuitW<<E1 as Engine>::Scalar>
    where
        C1: PastaCurve<Base=E1::Base, Scalar=E1::Scalar>,
        C2: PastaCurve<Base=E2::Base, Scalar=E2::Scalar>,
    {
        let (sign_start_r_x, sign_start_r_y) = C2::to_affine(&w_i.cred.signature.R);
        let (sign_ban_over_r_x, sign_ban_over_r_y, sign_ban_over_s) = if w_i.sign_ban_over.is_some() {
            let sign = w_i.sign_ban_over.unwrap();
            let (r_x, r_y) = C2::to_affine(&sign.R);
            (Some(r_x), Some(r_y), Some(sign.s.to_repr()))
        } else {
            (None, None, None)
        };

        let f_aux = FCircuitW::<<E1 as Engine>::Scalar>::new(
            w_i.cred.commitment, w_i.cred.k, w_i.cred.randomness,
            sign_start_r_x, sign_start_r_y, w_i.cred.signature.s.to_repr(),
            sign_ban_over_r_x, sign_ban_over_r_y, sign_ban_over_s,
            w_i.i,
            &w_i.cred.start_block, w_i.b_j.as_ref(), w_i.b_j_minus_1.as_ref(),
            w_i.r_i, w_i.r_i_plus_1,
        );

        f_aux
    }

    pub fn prove<'a, C1: PastaCurve, C2: PastaCurve<Base=C1::Scalar, Scalar=C1::Base>>(
        pp: &'a PublicParams<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>,
        z_i: IvcZ<E1::Scalar>,
        w_i: IvcW<C1, C2>,
        pi_ivc: &'a mut RecursiveSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>,
    ) -> &'a mut RecursiveSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>
    where
        C1: PastaCurve<Base=E1::Base, Scalar=E1::Scalar>,
        C2: PastaCurve<Base=E2::Base, Scalar=E2::Scalar>,
    {
        let circuit_z_i = FCircuitZ::<<E1 as Engine>::Scalar>::new::<C2>(z_i.com_k_i, z_i.h_j, z_i.pk_id_x, z_i.pk_id_y, z_i.pk_sp_x, z_i.pk_sp_y);
        let circuit_w_i = Self::f_w_from(w_i);

        let f_circuit = FCircuit::<<E1 as Engine>::Scalar>::new(circuit_z_i, circuit_w_i);
        let recursive_snark_res = pi_ivc.prove_step(pp, &f_circuit, &TrivialCircuit::default());
        assert!(recursive_snark_res.is_ok());

        return pi_ivc;
    }

    pub fn verify(
        pp: &PublicParams<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>,
        pi_ivc: &RecursiveSNARK<E1, E2, FCircuit<<E1 as Engine>::Scalar>, TrivialCircuit<<E2 as Engine>::Scalar>>,
        num_steps: usize,
        z_0: &IvcZ<E1::Scalar>,
    ) -> bool {
        let res = pi_ivc.verify(
            pp,
            num_steps,
            &[z_0.com_k_i, z_0.h_j, z_0.pk_id_x, z_0.pk_id_y, z_0.pk_sp_x, z_0.pk_sp_y],
            &[<E2 as Engine>::Scalar::ZERO]);

        res.is_ok()
    }
}

#[cfg(test)]
mod tests {
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
    use crate::traits::blocklist::AnonymousBlocklistingScheme;
    use crate::traits::commitment::CommitmentScheme;

    #[test]
    fn test_setup() {
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
        let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark)
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

        let t_1 = blocklist.get(1).unwrap();
        let t_0 = blocklist.get(0).unwrap();

        let r_1 = <E1 as Engine>::Scalar::random(csprng);
        let w_0 = FCircuitW::<<E1 as Engine>::Scalar>::new(com_k_b, k_b, r_com_b, sign_start_r_x, sign_start_r_y, sign_start_b.s.to_repr(), None, None, None, 0, &cold_start_block_b, Some(t_1), Some(t_0), r_com_b, r_1);
        let z_0 = FCircuitZ::<<E1 as Engine>::Scalar>::new::<VestaCurve>(com_k_b, t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        let primary_circuit = FCircuit::<<E1 as Engine>::Scalar>::new(z_0, w_0);

        let pp = Ivc::<E1, E2, S1, S2>::setup(&primary_circuit, &TrivialCircuit::default());
    }

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
        let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark)
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

        let circuit_z_0 = FCircuitZ::<<E1 as Engine>::Scalar>::new::<VestaCurve>(com_k_b, t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        let circuit_w_0 = FCircuitW::<<E1 as Engine>::Scalar>::new(com_k_b, k_b, r_com_b, sign_start_r_x, sign_start_r_y, sign_start_b.s.to_repr(), None, None, None, 0, &cold_start_block_b, Some(t_1), Some(t_0), r_com_b, r_1);
        let primary_circuit = FCircuit::<<E1 as Engine>::Scalar>::new(circuit_z_0, circuit_w_0);

        // let pp = IvcNova::<E1, E2, S1, S2>::setup(&primary_circuit, &TrivialCircuit::default());

        let z_0 = IvcZ { com_k_i: com_k_b, h_j: t_1.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y };
        let w_0: IvcW<PallasCurve, VestaCurve> = IvcW {
            cred: cred_b.clone(),
            sign_ban_over: None,
            b_j: Some(t_1.clone()),
            b_j_minus_1: Some(t_0.clone()),
            r_i: r_com_b,
            r_i_plus_1: r_1,
            i: 0,
        };
        let mut pi_sync = Ivc::<E1, E2, S1, S2>::base_proof(&pp, z_0.clone(), w_0);

        let t_2 = blocklist.get(2).unwrap();
        let r_2 = <E1 as Engine>::Scalar::random(csprng);
        let com_k_1 = PoseidonCommitment::<<E1 as Engine>::Scalar>::commit(&k_b, &r_1).unwrap();

        let z_1 = IvcZ { com_k_i: com_k_1, h_j: t_2.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y };
        let aux_1: IvcW<PallasCurve, VestaCurve> = IvcW {
            cred: cred_b,
            sign_ban_over: None,
            b_j: Some(t_2.clone()),
            b_j_minus_1: Some(t_1.clone()),
            r_i: r_com_b,
            r_i_plus_1: r_2,
            i: 1,
        };
        let pi_sync_1 = Ivc::<E1, E2, S1, S2>::prove(&pp, z_1, aux_1, &mut pi_sync);
        let verify_result = Ivc::<E1, E2, S1, S2>::verify(&pp, pi_sync_1, 1, &z_0.clone());
        assert_eq!(verify_result, true)
    }
}