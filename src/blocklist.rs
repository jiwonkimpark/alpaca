use std::collections::HashMap;
use std::io::Write;
use std::marker::PhantomData;
use circ::target::r1cs::{ProverData, VerifierData};
use circ::target::r1cs::spartan::{read_prover_data, read_verifier_data};
use circ::target::r1cs::spartan_opt::{read_preprocessed_spartan, write_r1cs_final, write_precompute};
use ff::{Field, PrimeField, PrimeFieldBits};
use libspartan::{Instance, NIZKGens};
use nova_snark::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::traits::circuit::TrivialCircuit;
use nova_snark::traits::Engine;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use crate::traits::blocklist::AnonymousBlocklistingScheme;
use crate::traits::commitment::CommitmentScheme;
use crate::traits::signature::SignatureScheme;
use crate::commitment::PoseidonCommitment;
use crate::curve::{PastaCurve, field_to_int};
use crate::errors::AnonymousBlocklistError;
use crate::signature::{SchnorrSignatureScheme, SchnorrSignature};
use crate::poseidon::{poseidon_hash};
use crate::proofs::relation_nova::ivc::f_circuit::{FCircuitW, FCircuit, FCircuitZ};
use crate::proofs::relation_nova::ivc::ivc::{IvcW, Ivc, IvcZ};
use crate::proofs::relation_nova::zksnark::ZkSnarkIVC;
use crate::util::{DomainSeparator, rand_field, run_shell_script, root_abs_path};
use crate::proofs::relation_post::zksnark::ZkSnarkPost;

#[derive(Debug, Copy, Clone)]
pub struct Cred<C, B, K, R, S> {
    pub k: K,
    pub randomness: R,
    pub commitment: C,
    pub start_block: B,
    pub signature: S,
}

impl<C: Default, B: Default, K: Default, R: Default, S: Default> Default for Cred<C, B, K, R, S> {
    fn default() -> Self {
        Self {
            k: Default::default(),
            randomness: Default::default(),
            commitment: Default::default(),
            start_block: Default::default(),
            signature: Default::default(),
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Block<H: PartialEq, F: PrimeField> {
    pub(crate) nonce: F,
    pub(crate) message_hash: H,
    pub(crate) tag: F,
    pub(crate) h: H,
    pub(crate) i: usize,
}

impl<H: Default + PartialEq, F: PrimeField> Default for Block<H, F> {
    fn default() -> Self {
        Self {
            nonce: Default::default(),
            message_hash: Default::default(),
            tag: Default::default(),
            h: Default::default(),
            i: 0,
        }
    }
}

impl<H: PartialEq, F: PrimeField> AsRef<Block<H, F>> for Block<H, F> {
    fn as_ref(&self) -> &Block<H, F> {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AuthToken<F: PrimeField, H> {
    pub(crate) nonce: F,
    pub(crate) tag: F,
    pub(crate) message_hash: H,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatableSyncProof<P, H, C> {
    ivc_proof: P,
    h_0: H,
    com_k_0: C,
    h_j: H, // j = start + i
    com_k_i: C, // i = number of IVC iterations
}

#[derive(Debug, Clone)]
pub struct UpdatableSyncStatus<R> {
    i: usize,
    r_i: R,
}

impl<R: Default> Default for UpdatableSyncStatus<R> {
    fn default() -> Self {
        UpdatableSyncStatus {
            i: 0,
            r_i: R::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProof<R, N, H, C> {
    post_proof: R,
    nova_proof: N,
    hash_0: H,
    com_k_0: C,
    hash_n_plus_1: H,
    com_k_l_plus_1: C,
    steps_count: usize,
}

pub struct BlocklistingScheme<C1, C2, E1, E2, S1, S2> {
    pub relation_post_prover_data: ProverData,
    pub relation_post_verifier_data: VerifierData,
    pub relation_post_gens: NIZKGens,
    pub relation_post_inst: Instance,
    _p1: PhantomData<C1>,
    _p2: PhantomData<C2>,
    _p3: PhantomData<E1>,
    _p4: PhantomData<E2>,
    _p5: PhantomData<S1>,
    _p6: PhantomData<S2>,
}

impl<C1, C2, E1, E2, S1, S2> AnonymousBlocklistingScheme for BlocklistingScheme<C1, C2, E1, E2, S1, S2>
where
    C1: PastaCurve,
    C2: PastaCurve<Base=C1::Scalar, Scalar=C1::Base>,
    C1::Point: Clone,
    C1::Base: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    C1::Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    <C2 as PastaCurve>::Scalar: PrimeField<Repr=[u8; 32]>,
    E1: Engine<Base=<E2 as Engine>::Scalar, Scalar=C1::Scalar>,
    E2: Engine<Base=<E1 as Engine>::Scalar, Scalar=C1::Base>,
    S1: RelaxedR1CSSNARKTrait<E1>,
    S2: RelaxedR1CSSNARKTrait<E2>,
    <E2 as Engine>::Scalar: PrimeField<Repr=[u8; 32]>,
{
    type PublicParams = PublicParams<E1, E2, Self::IvcPrimaryCircuit, Self::IvcSecondaryCircuit>;
    type PublicKey = C2::Point;
    type SecretKey = C2::Scalar;
    type ProverKey = ProverKey<E1, E2, Self::IvcPrimaryCircuit, Self::IvcSecondaryCircuit, S1, S2>;
    type VerifierKey = VerifierKey<E1, E2, Self::IvcPrimaryCircuit, Self::IvcSecondaryCircuit, S1, S2>;
    type TagNonce = C1::Scalar;
    type Cred = Cred<Self::Commitment, Self::Block, Self::K, Self::Random, Self::Signature>;
    type K = C1::Scalar;
    type Random = C1::Scalar;
    type AuthToken = AuthToken<Self::TagNonce, Self::HashValue>;
    type Block = Block<Self::HashValue, Self::TagNonce>;
    type Message = C1::Scalar;
    type Blocklist = Vec<Block<Self::HashValue, Self::TagNonce>>;
    type SyncProof = RecursiveSNARK<E1, E2, Self::IvcPrimaryCircuit, Self::IvcSecondaryCircuit>;
    type UpdatableSyncProof = UpdatableSyncProof<Self::SyncProof, Self::HashValue, Self::Commitment>;
    type UpdatableSyncStatus = UpdatableSyncStatus<Self::Random>;
    type AuthProof = AuthProof<libspartan::NIZK, CompressedSNARK<E1, E2, Self::IvcPrimaryCircuit, Self::IvcSecondaryCircuit, S1, S2>, Self::HashValue, Self::Commitment>;
    type VerificationKey = String;
    type Commitment = C1::Scalar;
    type Signature = SchnorrSignature<C2>;
    type HashValue = C1::Scalar;
    type BanOverSignatures = HashMap<u64, Self::Signature>;
    type Digest = C1::Scalar;
    type IvcPrimaryCircuit = FCircuit<E1::Scalar>;
    type IvcSecondaryCircuit = TrivialCircuit<E2::Scalar>;

    fn new() -> Self {
        let circ_path = root_abs_path() + "/circ-alpaca";
        let preprocess_sh_path = circ_path.clone() + "/alpaca/relations/preprocess.zsh";

        let args = vec![circ_path];
        run_shell_script(&*preprocess_sh_path, Some(args));

        let relation_post_prover_data = read_prover_data("P").unwrap();
        let relation_post_verifier_data = read_verifier_data("V").unwrap();
        let (relation_post_gens, relation_post_inst) = read_preprocessed_spartan("GENS", "INSTANCE").unwrap();

        let ivc_prover_data = read_prover_data("IVC_P").unwrap();
        write_precompute("IVC_PRECOMPUTE", &ivc_prover_data.precompute).unwrap();
        write_r1cs_final("IVC_R1CS", &ivc_prover_data.r1cs).unwrap();

        Self {
            relation_post_prover_data,
            relation_post_verifier_data,
            relation_post_gens,
            relation_post_inst,
            _p1: PhantomData,
            _p2: PhantomData,
            _p3: PhantomData,
            _p4: PhantomData,
            _p5: PhantomData,
            _p6: PhantomData,
        }
    }

    /// Setup the keys for the identity provider, the service provider, the zkSNARK scheme of
    /// relation Post, and the zkSNARK and IVC scheme of relation Nova
    fn setup(&self) -> Result<
        (
            Self::PublicParams,
            Self::PublicKey,
            Self::PublicKey,
            Self::PublicKey,
            Self::ProverKey,
            Self::SecretKey,
            Self::SecretKey,
            Self::VerificationKey,
            Self::VerifierKey
        ),
        AnonymousBlocklistError
    >
    {
        let (pk_sp, sk_sp) = SchnorrSignatureScheme::<C2>::keygen();
        let (pk_id, sk_id) = SchnorrSignatureScheme::<C2>::keygen();

        let primary_circuit = self.default_circuit(&pk_id, &sk_id, &pk_sp);
        let pp_ivc = Ivc::<E1, E2, S1, S2>::setup(&primary_circuit, &TrivialCircuit::default());
        let (pk_zksnark_ivc, sk_zksnark_ivc) = ZkSnarkIVC::<E1, E2, S1, S2>::setup(&pp_ivc);

        let r3 = Self::SecretKey::random(rand::thread_rng());
        let g = C2::generator();
        let pk_zksnark = C2::mul(&g, &r3);

        Ok((pp_ivc, pk_sp, pk_id, pk_zksnark, pk_zksnark_ivc, sk_sp, sk_id, String::from("vk_r"), sk_zksnark_ivc))
    }

    /// Generate a default circuit for the key generation
    ///
    /// Arguments
    /// * `pk_id` - public key of identity provider
    /// * `sk_id` - secret key of identity provider
    /// * `pk_sp` - public key of service provider
    fn default_circuit(&self, pk_id: &Self::PublicKey, sk_id: &Self::SecretKey, pk_sp: &Self::PublicKey) -> Self::IvcPrimaryCircuit {
        let (pk_id_x, pk_id_y) = C2::to_affine(&pk_id);
        let (pk_sp_x, pk_sp_y) = C2::to_affine(&pk_sp);

        let mut dummy_blocklist = Self::initialize_blocklist(&self).unwrap();
        let (k, r_com, com_k) =
            self.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            self.register_idp(sk_id.clone(), com_k.clone(), dummy_blocklist.clone()).unwrap();
        let _ = self.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();
        let (sign_start_r_x, sign_start_r_y) = C2::to_affine(&sign_start.R);

        let mut csprng = OsRng;
        let b_0 = dummy_blocklist.get(0).unwrap();
        let r_1 = C1::Scalar::random(csprng);

        let w_0 = FCircuitW::<C1::Scalar>::new(com_k, k, r_com, sign_start_r_x, sign_start_r_y, sign_start.s.to_repr(), None, None, None, 0, &cold_start_block, Some(b_0), None, r_com, r_1);
        let z_0 = FCircuitZ::<C1::Scalar>::new::<C2>(com_k, b_0.h, pk_id_x, pk_id_y, pk_sp_x, pk_sp_y);
        let f_circuit = Self::IvcPrimaryCircuit::new(z_0, w_0);

        f_circuit
    }

    /// The user's first step of registration. The user first chooses its key k and commits to k.
    fn register_user1(&self) -> Result<(Self::K, Self::Random, Self::Commitment), AnonymousBlocklistError> {
        let k = rand_field::<Self::K>();
        let r_com = rand_field::<Self::Random>();
        let com_k = PoseidonCommitment::<C1::Scalar>::commit(&k, &r_com).unwrap();

        Ok((k, r_com, com_k))
    }

    /// The user's second step of registration
    ///
    /// Arguments
    /// * `k` - the key (for PRF) that the user has chosen
    /// * `r` - the randomness used for `com_k`
    /// * `com_k` - user's commitment to the key k
    /// * `b_start` - the cold-start block of the user
    /// * `sig` - the identity provider's signature
    fn register_user2(&self, k: Self::K, r: Self::Random, com_k: &Self::Commitment, b_start: &Self::Block, sig: Self::Signature) -> Result<Self::Cred, AnonymousBlocklistError> {
        let cred = Self::Cred {
            commitment: com_k.clone(),
            start_block: b_start.clone(),
            k: k,
            randomness: r,
            signature: sig,
        };
        Ok(cred)
    }

    /// Identity provider's step of registration. Identity provider sets the user's cold-start block
    /// by choosing the last block of current blocklist and approves the user's registration by
    /// signing on cold-start block and the user's commitment to k.
    ///
    /// Arguments
    /// * `sk_id` - the secret key of identity provider
    /// * `com_k` - user's commitment to the key k
    /// * `blocklist` - current blocklist
    fn register_idp(&self, sk_id: Self::SecretKey, com_k: Self::Commitment, blocklist: Self::Blocklist) -> Result<(Self::Block, Self::Signature), AnonymousBlocklistError> {
        let b_start = blocklist.last().unwrap().clone();
        let sign_msg = [com_k, b_start.nonce, b_start.tag, b_start.h].to_vec();
        let signature: Self::Signature = SchnorrSignatureScheme::sign(&sk_id, &sign_msg).unwrap();
        Ok((b_start, signature))

    }

    /// Generate a token from a message and the author's credential using PRF
    ///
    /// Arguments
    /// * `cred` - user's credential
    /// * `message` - user's message
    fn extract_token(&self, cred: &Self::Cred, message: &Self::Message) -> Result<Self::AuthToken, AnonymousBlocklistError> {
        let message_hash = poseidon_hash::<C1::Scalar>([message.clone()].to_vec(), DomainSeparator::HASH.value());

        let nonce = rand_field::<Self::TagNonce>();
        let tag = poseidon_hash::<C1::Scalar>([cred.k, nonce, message_hash].to_vec(), DomainSeparator::PRF.value());
        let token = Self::AuthToken {
            nonce,
            tag,
            message_hash,
        };
        Ok(token)
    }

    /// Initialize the blocklist
    fn initialize_blocklist(&self) -> Result<Self::Blocklist, AnonymousBlocklistError> {
        let mut blocklist = Vec::new();

        let nonce = <Self::TagNonce>::ZERO;
        let hash = poseidon_hash::<C1::Scalar>([<Self::TagNonce>::ZERO].to_vec(), DomainSeparator::HASH.value());
        let b_0 = Self::Block {
            nonce,
            message_hash: <Self::TagNonce>::ZERO,
            tag: poseidon_hash::<C1::Scalar>([<Self::TagNonce>::ZERO].to_vec(), DomainSeparator::PRF.value()),
            h: hash,
            i: 0,
        };
        blocklist.push(b_0);

        Ok(blocklist)
    }

    /// Add a token to the blocklist to block the corresponding author from posting.
    ///
    /// Arguments
    /// * `token` - the token of the message that violated the service policy
    /// * `blocklist` - current blocklist
    fn add_token_to_blocklist<'a>(&'a self, token: &Self::AuthToken, blocklist: &'a mut Self::Blocklist) -> Result<&mut Self::Blocklist, AnonymousBlocklistError> {
        let l = blocklist.len();
        let b_last = blocklist.last().unwrap();
        let message = [b_last.nonce, b_last.message_hash, b_last.tag, b_last.h].to_vec();
        let hash_of_last = poseidon_hash::<C1::Scalar>(message, DomainSeparator::HASH.value());

        let new_block = Self::Block {
            nonce: token.nonce,
            message_hash: token.message_hash,
            tag: token.tag,
            h: hash_of_last,
            i: l,
        };
        blocklist.push(new_block);

        Ok(blocklist)
    }

    /// Conceptually removes a block from the blocklist by signing on the target block.
    /// Generate a ban_over signature and add that to the set ban_over_signatures.
    ///
    /// Arguments
    /// * `block` - the block that the service provider wants to unblock.
    /// * `sk_sp` - secret key of service provider
    /// * `ban_over_signatures` - the set of all ban-over signatures
    fn remove_from_blocklist<'a>(&'a self, block: Self::Block, sk_sp: &Self::SecretKey, ban_over_signatures: &'a mut Self::BanOverSignatures) -> Result<&mut Self::BanOverSignatures, AnonymousBlocklistError> {
        let message = [block.nonce, block.message_hash, block.tag, block.h].to_vec();
        let sign_ban_over: Self::Signature = SchnorrSignatureScheme::sign(sk_sp, &message).unwrap();

        ban_over_signatures.insert(field_to_int::<Self::TagNonce>(block.tag), sign_ban_over);

        Ok(ban_over_signatures)
    }

    /// Generate a digest of the blocklist, which is the hash of the last block.
    ///
    /// Arguments
    /// * `blocklist` - current blocklist
    fn digest_blocklist(&self, blocklist: &Self::Blocklist) -> Result<Self::Digest, AnonymousBlocklistError> {
        let last_block = blocklist.last().unwrap().clone();

        let digest = poseidon_hash::<C1::Scalar>([last_block.nonce, last_block.message_hash, last_block.tag, last_block.h].to_vec(), DomainSeparator::HASH.value());

        Ok(digest)
    }

    // TODO: Re-implement Audit
    // fn audit_blocklist(
    //     &self,
    //     pp: &Self::PublicParams,
    //     message: &Self::Message,
    //     cred: &Self::Cred,
    //     blocklist: &Self::Blocklist,
    //     ban_over_signatures: &Self::BanOverSignatures,
    //     public_keys: (&Self::PublicKey, &Self::PublicKey, &Self::PublicKey, &Self::ProverKey),
    //     verification_key: (&Self::VerificationKey, &Self::VerifierKey),
    // ) -> Result<bool, AnonymousBlocklistError> {
    //     let n = blocklist.len();
    //     let t_n_minus_1 = &blocklist[n - 1];
    //     let t_n_minus_2 = blocklist.get(n - 2);
    //     let tag_n_minus_1 = t_n_minus_1.tag;
    //     let sign_ban_over_n = ban_over_signatures.get(&field_to_int::<Self::TagNonce>(tag_n_minus_1));
    //     let (usync_l, status_l) =
    //         self.synchronize_blocklist(pp, public_keys.1, public_keys.0, blocklist, ban_over_signatures, cred, None, None).unwrap();
    //
    //     let a = self.extract_token(cred, message).unwrap();
    //     let pi_auth = self.authorize_token(pp, &a, cred, public_keys, t_n_minus_1, t_n_minus_2, sign_ban_over_n, usync_l, status_l).unwrap();
    //     let d = self.digest_blocklist(blocklist)?;
    //     Ok(self.verify_auth_proof(&a, message, d, public_keys.1, public_keys.0, verification_key, &pi_auth).unwrap())
    // }

    /// This function is invoked by authorize_token in order to re-randomize the final commitment.
    /// Given `usync_proof_l` and `usync_status_l`, run IVC function F that only re-randomizes
    /// the commitment in `usync_proof_l`, `com_k_l` to `com_k_l_plus_1`. Then output the updated
    /// proof and status `usync_proof_l_plus_1` and `usync_status_l_plus_1`.
    ///
    /// Arguments
    /// * `pp` - public parameters
    /// * `pk_id` - public key of identity provider
    /// * `pk_sp` - public key of service provider
    /// * `cred` - user's credential
    /// * `usync_proof_l` - the proof from iterating l = (len(block) - start) times of the updatable synchronization protocol
    /// * `usync_status_l` - the status from iterating l = (len(block) - start) times of the updatable synchronization protocol
    fn rerandomize_usync_proof(
        &self,
        pp: &Self::PublicParams,
        pk_id: &Self::PublicKey,
        pk_sp: &Self::PublicKey,
        cred: &Self::Cred,
        usync_proof_l: Option<Self::UpdatableSyncProof>,
        usync_status_l: Option<Self::UpdatableSyncStatus>,
    ) -> Result<(Self::UpdatableSyncProof, Self::UpdatableSyncStatus), AnonymousBlocklistError> {
        let h_0 = poseidon_hash::<C1::Scalar>([<Self::TagNonce>::ZERO].to_vec(), DomainSeparator::HASH.value());
        let com_k_0: C1::Scalar = C1::Scalar::ZERO;

        let r_l_plus_1 = rand_field::<Self::Random>();

        let (h_n_plus_1, com_k_l, r_l, l) = {
            (usync_proof_l.clone().unwrap().h_j, usync_proof_l.clone().unwrap().com_k_i, usync_status_l.clone().unwrap().r_i, usync_status_l.clone().unwrap().i)
        };

        let ivc_proof_l_plus_1 = {
            let z_l = IvcZ::<C1::Scalar>::new::<C2>(com_k_l, h_n_plus_1, pk_id, pk_sp);
            let w_l = IvcW::<C1, C2>::new(cred, None, None, None, r_l, r_l_plus_1, l);

            Ivc::<E1, E2, S1, S2>::prove(pp, z_l, w_l, &mut usync_proof_l.unwrap().ivc_proof).clone()
        };

        let f_result = Self::f(self, &h_n_plus_1, &com_k_l, pk_id, pk_sp, &cred, None, None, None, &r_l, &r_l_plus_1);

        let (com_k_l_plus_1, h_n_plus_1) = match f_result {
            Ok(result) => { (result.0, result.1) }
            Err(err) => { return Err(err); }
        };

        let usync_proof_l_plus_1 = UpdatableSyncProof {
            ivc_proof: ivc_proof_l_plus_1,
            h_0,
            com_k_0,
            h_j: h_n_plus_1,
            com_k_i: com_k_l_plus_1,
        };
        let usync_status_l_plus_1 = UpdatableSyncStatus {
            i: l + 1,
            r_i: r_l_plus_1.clone(),
        };

        Ok((usync_proof_l_plus_1, usync_status_l_plus_1))

    }

    /// Given ith iteration's result `usync_proof_i` and `usync_status_i`, check if the user's
    /// credential `cred` is blocked by `b_j`. If not, run (i + 1)th iteration of IVC function F
    /// and generate an updated `usync_proof` and `usync_status` for (i + 1)th iteration.
    ///
    /// Arguments
    /// * `pp` - public parameters
    /// * `pk_id` - public key of identity provider
    /// * `pk_sp` - public key of service provider
    /// * `b_j` - the j = (start + i)th block
    /// * `b_j_minus_1` - the j - 1 = (start + i - 1)th block
    /// * `sign_ban_over_j` = the ban_over signature for jth block
    /// * `cred` - user's credential
    /// * `usync_proof_i` - the proof from iterating i times of the updatable synchronization protocol from cold-start block
    /// * `usync_status_i` - the status from iterating i times of the updatable synchronization protocol from cold-start block
    fn updatable_synchronize(
        &self,
        pp: &Self::PublicParams,
        pk_id: &Self::PublicKey,
        pk_sp: &Self::PublicKey,
        b_j: &Self::Block,
        b_j_minus_1: Option<&Self::Block>,
        sign_ban_over_j: Option<&Self::Signature>,
        cred: &Self::Cred,
        usync_proof_i: Option<Self::UpdatableSyncProof>,
        usync_status_i: Option<Self::UpdatableSyncStatus>,
    ) -> Result<(Self::UpdatableSyncProof, Self::UpdatableSyncStatus), AnonymousBlocklistError> {
        let h_0 = poseidon_hash::<C1::Scalar>([<Self::TagNonce>::ZERO].to_vec(), DomainSeparator::HASH.value());
        let com_k_0: C1::Scalar = C1::Scalar::ZERO;

        let r_i_plus_1 = rand_field::<Self::Random>();

        let (h_j, com_k_i, b_j_minus_1, r_i, i) =
        if cred.start_block == b_j.clone() {
            (h_0, com_k_0, None, rand_field::<C1::Scalar>(), 0)
        } else {
            let usync_status = usync_status_i.unwrap();
            (usync_proof_i.clone().unwrap().h_j, usync_proof_i.clone().unwrap().com_k_i, b_j_minus_1, usync_status.r_i, usync_status.i)
        };
        
        let ivc_proof_i_plus_1 = if cred.start_block == b_j.clone() {
            let z_0 = IvcZ::<C1::Scalar>::new::<C2>(com_k_i, h_j, pk_id, pk_sp);
            let w_0 = IvcW::<C1, C2>::new(cred, None, Some(b_j), b_j_minus_1, r_i, r_i_plus_1, 0); // sign_ban_over is always None for cold start block

            let mut empty_sync_proof = Ivc::<E1, E2, S1, S2>::base_proof(pp, z_0.clone(), w_0.clone());
            Ivc::<E1, E2, S1, S2>::prove(pp, z_0, w_0, &mut empty_sync_proof).clone()
        } else {
            let z_i = IvcZ::<C1::Scalar>::new::<C2>(com_k_i, h_j, pk_id, pk_sp);
            let w_i = IvcW::<C1, C2>::new(cred, sign_ban_over_j, Some(b_j), b_j_minus_1, r_i, r_i_plus_1, i);

            Ivc::<E1, E2, S1, S2>::prove(pp, z_i, w_i, &mut usync_proof_i.unwrap().ivc_proof).clone()
        };
        
        let f_result = Self::f(self, &h_j, &com_k_i, pk_id, pk_sp, &cred, sign_ban_over_j, Some(b_j), b_j_minus_1, &r_i, &r_i_plus_1);

        let (com_k_i_plus_1, h_j_plus_1) = match f_result {
            Ok(result) => { (result.0, result.1) }
            Err(err) => { return Err(err); }
        };

        let usync_proof_i_plus_1 = UpdatableSyncProof {
            ivc_proof: ivc_proof_i_plus_1,
            h_0,
            com_k_0,
            h_j: h_j_plus_1,
            com_k_i: com_k_i_plus_1,
        };
        let usync_status_i_plus_1 = UpdatableSyncStatus {
            i: i + 1,
            r_i: r_i_plus_1.clone(),
        };

        Ok((usync_proof_i_plus_1, usync_status_i_plus_1))
    }

    /// Assume that the user has usync_proof_i that is the result of iterating from cold-start block (start)
    /// to (start + i)th block. Iterate updatable_synchronize from this block to the last block and
    /// return the pair of updatable synchronization proof and status.
    ///
    /// Arguments
    /// * `pp` - public parameters
    /// * `pk_id` - public key of identity provider
    /// * `pk_sp` - public key of service provider
    /// * `blocklist` - current blocklist
    /// * `ban_over_signatures` - the set of ban_over signatures signed by the service provider
    /// * `cred` - user's credential
    /// * `usync_proof_i` - the proof from iterating i times of the updatable synchronization protocol from cold-start block
    /// * `usync_status_i` - the status from iterating i times of the updatable synchronization protocol from cold-start block
    fn synchronize(
        &self,
        pp: &Self::PublicParams,
        pk_id: &Self::PublicKey,
        pk_sp: &Self::PublicKey,
        blocklist: &Self::Blocklist,
        ban_over_signatures: &Self::BanOverSignatures,
        cred: &Self::Cred,
        usync_proof_i: Option<Self::UpdatableSyncProof>,
        usync_status_i: Option<Self::UpdatableSyncStatus>,
    ) -> Result<(Option<Self::UpdatableSyncProof>, Option<Self::UpdatableSyncStatus>), AnonymousBlocklistError> {
        let start = if usync_status_i.is_some() { usync_status_i.clone().unwrap().i + cred.start_block.i } else { cred.start_block.i };
        let end = blocklist.len();

        let mut usync_proof = usync_proof_i;
        let mut usync_status = usync_status_i;

        for i in start..end {
            let b_i = &blocklist[i];
            let b_i_minus_1 = if i > 0 { Some(&blocklist[i-1]) } else { None };
            let sign_ban_over_i = ban_over_signatures.get(&field_to_int::<Self::TagNonce>(b_i.tag));

            //update usync values
            let result
                = self.updatable_synchronize(pp, pk_id, pk_sp, b_i, b_i_minus_1, sign_ban_over_i, cred, usync_proof, usync_status);

            if let Err(AnonymousBlocklistError::UnauthorizedUser) = result {
                return Err(AnonymousBlocklistError::UnauthorizedUser);
            }

            let (usync_proof_i_plus_1, usync_status_i_plus_1) = result.unwrap();
            usync_proof = Some(usync_proof_i_plus_1);
            usync_status = Some(usync_status_i_plus_1);
        }

        Ok((usync_proof, usync_status))
    }

    /// Generate an authorization proof that proves the user (`cred`) can post a new message, by
    /// running zkSNARKs for relation Post and Nova.
    ///
    /// Arguments
    /// * `pp` - public parameters
    /// * `token` - token to authenticate
    /// * `cred` - user's credential
    /// * `message` - user's message to relation_post
    /// * `public_keys` - public keys
    /// * `usync_proof_l` - the proof from iterating l = (len(block) - start) times of the updatable synchronization protocol
    /// * `usync_status_l` - the status from iterating l = (len(block) - start) times of the updatable synchronization protocol
    fn authorize_token(
        &self,
        pp: &Self::PublicParams,
        token: &Self::AuthToken,
        cred: &Self::Cred,
        public_keys: (&Self::PublicKey, &Self::PublicKey, &Self::PublicKey, &Self::ProverKey),
        usync_proof_l: Option<Self::UpdatableSyncProof>,
        usync_status_l: Option<Self::UpdatableSyncStatus>,
    ) -> Result<Self::AuthProof, AnonymousBlocklistError> {
        let usync_prime = self.rerandomize_usync_proof(pp, public_keys.1, public_keys.0, cred, usync_proof_l, usync_status_l);
        let (usync_proof_l_plus_1, usync_status_l_plus_1) = match usync_prime {
            Ok(result) => { result }
            Err(err) => { return Err(err); }
        };

        let nova_proof = ZkSnarkIVC::<E1, E2, S1, S2>::prove(pp, public_keys.3, &usync_proof_l_plus_1.ivc_proof);
        let post_proof = ZkSnarkPost::<C1, C2>::prove(
            token,
            public_keys.1.clone(),
            usync_proof_l_plus_1.com_k_i,
            cred.k,
            usync_status_l_plus_1.r_i,
            &cred.signature,
            cred.commitment,
            &cred.start_block,
            cred.randomness,
            &self.relation_post_prover_data,
            &self.relation_post_gens,
            &self.relation_post_inst
        ).expect("Generating proof for Relation R has failed");

        let auth_proof = Self::AuthProof {
            post_proof,
            nova_proof,
            hash_0: usync_proof_l_plus_1.h_0,
            com_k_0: usync_proof_l_plus_1.com_k_0,
            hash_n_plus_1: usync_proof_l_plus_1.h_j,
            com_k_l_plus_1: usync_proof_l_plus_1.com_k_i,
            steps_count: usync_status_l_plus_1.i,
        };

        Ok(auth_proof)
    }

    /// Verify the auth_proof generated by `authorize_token` above.
    ///
    /// Arguments
    /// * `token` - token to authorize
    /// * `message` - user's message to relation_post
    /// * `digest` - the digest of blocklist (hash of the last block)
    /// * `pk_id` - public key of identity provider
    /// * `pk_sp` - public key of service provider
    /// * `ver_keys` - verification keys for zkSNARKs (Post and Nova)
    /// * `auth_proof` - authorization proof gained through `Self::authorize_token`
    fn verify_auth_proof(
        &self,
        token: &Self::AuthToken,
        message: &Self::Message,
        digest: Self::Digest,
        pk_id: &Self::PublicKey,
        pk_sp: &Self::PublicKey,
        ver_keys: (&Self::VerificationKey, &Self::VerifierKey),
        auth_proof: &Self::AuthProof,
    ) -> Result<bool, AnonymousBlocklistError> {
        if digest != auth_proof.hash_n_plus_1 || token.message_hash != poseidon_hash::<C1::Scalar>([message.clone()].to_vec(), DomainSeparator::HASH.value()) {
            return Ok(false);
        }

        let post_proof = &auth_proof.post_proof;
        let post_proof_verify_result = ZkSnarkPost::<C1, C2>::verify(token, pk_id.clone(), auth_proof.com_k_l_plus_1, &self.relation_post_gens, &self.relation_post_inst, &post_proof, &self.relation_post_verifier_data).unwrap();
        if !post_proof_verify_result {
            return Ok(false);
        }

        let nova_proof = &auth_proof.nova_proof;
        let z_0 = IvcZ::<C1::Scalar>::new::<C2>(auth_proof.com_k_0, auth_proof.hash_0, pk_id, pk_sp);
        let nova_proof_verify_result = ZkSnarkIVC::<E1, E2, S1, S2>::verify(ver_keys.1, nova_proof, auth_proof.steps_count, z_0);
        if !nova_proof_verify_result {
            return Ok(false);
        }

        Ok(true)
    }

    /// Function F for IVC given the results of i iterations of function F previously. It checks
    /// if the token in `b_j` references the user `cred`, and if so, if the user has the
    /// corresponding ban-over signature `sign_ban_over_j`. Function F also checks the validity of
    /// commitments, cold-start signature, etc. If all the checks pass, it outputs the (i + 1)th
    /// re-randomized commitment and the hash of `b_j`.
    ///
    /// Arguments
    /// * `h_j` - the hash of (j - 1) = (start + i - 1)th block
    /// * `com_k_i` - the ith re-randomized commitment
    /// * `pk_id` - public key of identity provider
    /// * `pk_sp` - public key of service provider
    /// * `cred` - user's credential
    /// * `sign_ban_over_j` - the ban_over signature for j = (start + i)th block
    /// * `b_j` - jth block
    /// * `b_j_minus_1` - (j - 1)th block
    /// * `r_i` - the randomness for ith re-randomized commitment
    /// * `r_i_plus_1` - the randomness that will be used to generate the (i + 1)th re-randomized commitment
    fn f(
        &self,
        h_j: &Self::HashValue,
        com_k_i: &Self::Commitment,
        pk_id: &Self::PublicKey,
        pk_sp: &Self::PublicKey,
        cred: &Self::Cred,
        sign_ban_over_j: Option<&Self::Signature>,
        b_j: Option<&Self::Block>,
        b_j_minus_1: Option<&Self::Block>,
        r_i: &Self::Random,
        r_i_plus_1: &Self::Random,
    ) -> Result<(Self::Commitment, Self::HashValue), AnonymousBlocklistError> {
        if b_j.is_none() {
            let com_k_i_open = PoseidonCommitment::<C1::Scalar>::open(&cred.k, com_k_i, r_i).unwrap();
            if !com_k_i_open {
                return Err(AnonymousBlocklistError::InvalidCommitment);
            }

            let next_iter_commitment = PoseidonCommitment::<C1::Scalar>::commit(&cred.k, r_i_plus_1).unwrap();
            return Ok((next_iter_commitment, *h_j))
        }

        let block_j = b_j.unwrap();

        let open_result = PoseidonCommitment::<C1::Scalar>::open(&cred.k, &cred.commitment, &cred.randomness).unwrap();
        if !open_result {
            return Err(AnonymousBlocklistError::InvalidCommitment);
        }

        let b_start = cred.start_block.clone();
        let message = [cred.commitment, b_start.nonce, b_start.tag, b_start.h].to_vec();
        SchnorrSignatureScheme::verify(pk_id, &message, &cred.signature).unwrap();

        if *block_j != cred.start_block {
            let com_k_i_open = PoseidonCommitment::<C1::Scalar>::open(&cred.k, com_k_i, r_i).unwrap();
            if !com_k_i_open {
                return Err(AnonymousBlocklistError::InvalidCommitment);
            }

            // t_i previous is not none since we always have s start block when calling it in usync
            let b_j_minus_1_hashed = poseidon_hash::<C1::Scalar>([b_j_minus_1.unwrap().nonce, b_j_minus_1.unwrap().message_hash, b_j_minus_1.unwrap().tag, b_j_minus_1.unwrap().h].to_vec(), DomainSeparator::HASH.value());
            if h_j != &b_j_minus_1_hashed {
                return Err(AnonymousBlocklistError::InvalidHash);
            }

            let tag = poseidon_hash::<C1::Scalar>([cred.k, block_j.nonce, block_j.message_hash].to_vec(), DomainSeparator::PRF.value());
            let sign_msg = [block_j.nonce, block_j.message_hash, block_j.tag, block_j.h].to_vec();
            if tag == block_j.tag {
                if sign_ban_over_j.is_none() {
                    return Err(AnonymousBlocklistError::UnauthorizedUser);
                } else {
                    if !SchnorrSignatureScheme::verify(pk_sp, &sign_msg, sign_ban_over_j.unwrap()).unwrap() {
                        return Err(AnonymousBlocklistError::UnauthorizedUser);
                    }
                }
            }
        }

        let next_iter_commitment = PoseidonCommitment::<C1::Scalar>::commit(&cred.k, r_i_plus_1).unwrap();
        let message = [block_j.nonce, block_j.message_hash, block_j.tag, block_j.h].to_vec();
        let curr_block_hash = poseidon_hash::<C1::Scalar>(message, DomainSeparator::HASH.value());

        Ok((next_iter_commitment, curr_block_hash))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use ff::Field;
    use nova_snark::provider::{PallasEngine, VestaEngine};
    use nova_snark::provider::ipa_pc::EvaluationEngine;
    use nova_snark::spartan::snark::RelaxedR1CSSNARK;
    use pasta_curves::pallas;
    use crate::traits::blocklist::AnonymousBlocklistingScheme;
    use crate::blocklist::BlocklistingScheme;
    use crate::curve::{PallasCurve, PastaCurve, VestaCurve};
    use crate::errors::AnonymousBlocklistError::UnauthorizedUser;

    #[test]
    fn test_blocklist_initialize() {
        let blocklisting_scheme = BlocklistingScheme::<
            PallasCurve,
            VestaCurve,
            PallasEngine,
            VestaEngine,
            RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
            RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
        >::new();
        let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark) = blocklisting_scheme.setup().unwrap();

        let result = blocklisting_scheme.initialize_blocklist();
        assert!(result.as_ref().err().is_none());

        let blocklist = result.unwrap();
        assert_eq!(blocklist.len(), 1)
    }

    #[test]
    fn test_registration() {
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

        assert_eq!(cred.start_block, last_block);
        assert_eq!(cred.k, k);
        assert_eq!(cred.commitment, com_k);
        assert_eq!(cred.randomness, r_com);
        assert_eq!(cred.signature, sign_start);
    }

    #[test]
    fn test_extract_token() {
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
        let result = scheme.extract_token(&cred, &msg1);

        assert!(result.err().is_none())
    }

    #[test]
    /// test synchronize when user runs synchronization protocol for the first time.
    fn test_synchronize_without_usync_proof() {
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
        let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);

        // set blocklist and ban_over_signatures map
        let blocklist = scheme.initialize_blocklist().unwrap();
        let mut ban_over_signatures = HashMap::new();

        // set user
        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set usync proof and usync status as None since it's user's first time to run sync
        let result = scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &cred, None, None);
        assert!(result.err().is_none())
    }

    #[test]
    /// test synchronize when user's ban is lifted after blocked
    fn test_synchronize_success_after_ban_over() {
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
        let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);

        // set blocklist and ban_over_signatures map
        let mut blocklist = scheme.initialize_blocklist().unwrap();
        let mut ban_over_signatures = HashMap::new();

        // set user
        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set message and token that will be blocked
        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token1 = scheme.extract_token(&cred, &msg1).unwrap();

        // add user's token to the blocklist
        blocklist = scheme.add_token_to_blocklist(&token1, &mut blocklist).unwrap().clone();

        let ban_over_block = blocklist.last().unwrap().clone();
        ban_over_signatures = scheme.remove_from_blocklist(ban_over_block, &sk_sp, &mut ban_over_signatures).unwrap().clone();

        // set a new message and token
        let msg2 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token2 = scheme.extract_token(&cred, &msg2).unwrap();

        // set usync proof and usync status as None since it's user's first time to run sync
        let result = scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &cred, None, None);
        assert!(result.err().is_none())
    }

    #[test]
    fn test_authorization_success() {
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
        let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);

        // set blocklist and ban_over_signatures map
        let blocklist = scheme.initialize_blocklist().unwrap();
        let mut ban_over_signatures = HashMap::new();

        // set user
        let last_block_for_register = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set message and token
        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token = scheme.extract_token(&cred, &msg1).unwrap();

        let len = blocklist.len();
        let last_block = blocklist[len - 1].clone(); // blocklist[0]
        let last_prev_block = if len - 1 > 0 {
            Some(&blocklist[len - 2])
        } else {
            None
        };

        let (usync_proof, usync_status) =
            scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &cred, None, None).unwrap();

        let result =
            scheme.authorize_token(&pp, &token, &cred, public_keys, usync_proof, usync_status);

        assert_eq!(result.unwrap().steps_count, 2);
    }

    #[test]
    fn test_usync_fail() {
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
        let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);

        // set blocklist and ban_over_signatures map
        let mut blocklist = scheme.initialize_blocklist().unwrap();
        let mut ban_over_signatures = HashMap::new();

        // set user
        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set message and token that will be blocked
        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token1 = scheme.extract_token(&cred, &msg1).unwrap();

        // usync should succeed because user is not blocked yet.
        let (mut usync_proof, mut usync_status) =
            scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &cred, None, None).unwrap();

        // set a new message and token
        let msg2 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token2 = scheme.extract_token(&cred, &msg2).unwrap();

        // add user's token to the blocklist
        blocklist = scheme.add_token_to_blocklist(&token1, &mut blocklist).unwrap().clone();

        // usync should fail
        let result =
            scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &cred, None, None);

        assert_eq!(result.err(), Some(UnauthorizedUser));
    }

    #[test]
    /// Test authoriazation when user's ban is lifted after blocked
    /// Since user's ban is over, user should be able to authorize
    fn test_authorization_success_after_ban_over() {
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
        let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);

        // set blocklist and ban_over_signatures map
        let mut blocklist = scheme.initialize_blocklist().unwrap();
        let mut ban_over_signatures = HashMap::new();

        // set user
        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set message and token that will be blocked
        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token1 = scheme.extract_token(&cred, &msg1).unwrap();

        // add user's token to the blocklist
        blocklist = scheme.add_token_to_blocklist(&token1, &mut blocklist).unwrap().clone();

        let ban_over_block = blocklist.last().unwrap().clone();
        ban_over_signatures = scheme.remove_from_blocklist(ban_over_block, &sk_sp, &mut ban_over_signatures).unwrap().clone();

        // set a new message and token
        let msg2 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token2 = scheme.extract_token(&cred, &msg2).unwrap();

        // sync
        let (usync_proof, usync_status) =
            scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &cred, None, None).unwrap();

        // auth should succeed since ban over signature is in the hash map.
        let len = blocklist.len();
        let last_block = blocklist[len - 1].clone();
        let last_prev_block = if len - 1 > 0 { Some(&blocklist[len - 2]) } else { None };

        let ban_over_signature = ban_over_signatures.iter().last().unwrap().1;
        let auth_proof =
            scheme.authorize_token(&pp, &token2, &cred, public_keys, usync_proof, usync_status).unwrap();

        let digest = scheme.digest_blocklist(&blocklist).unwrap();

        let result = scheme.verify_auth_proof(&token2, &msg2, digest, &pk_id, &pk_sp, (&vk_r, &vk_zksnark), &auth_proof);
        assert!(result.err().is_none())
    }

    #[test]
    fn test_verification() {
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
        let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);
        let verification_keys = (&vk_r, &vk_zksnark);

        // set blocklist and ban_over_signatures map
        let blocklist = scheme.initialize_blocklist().unwrap();
        let mut ban_over_signatures = HashMap::new();

        // set user
        let last_block_for_register = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set message and token
        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token = scheme.extract_token(&cred, &msg1).unwrap();

        let len = blocklist.len();
        let last_block = blocklist[len - 1].clone();
        let last_prev_block = if len - 1 > 0 {
            Some(&blocklist[len - 2])
        } else {
            None
        };

        // sync
        let (usync_proof, usync_status) =
            scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &cred, None, None).unwrap();

        // auth
        let auth_proof =
            scheme.authorize_token(&pp, &token, &cred, public_keys, usync_proof, usync_status).unwrap();

        // digest for verification
        let digest = scheme.digest_blocklist(&blocklist).unwrap();

        // verification
        let result = scheme.verify_auth_proof(&token, &msg1, digest, &pk_id, &pk_sp, verification_keys, &auth_proof);
        assert!(result.clone().err().is_none());
    }

    // #[test]
    // fn test_audit() {
    //     let scheme = BlocklistingScheme::<
    //         PallasCurve,
    //         VestaCurve,
    //         PallasEngine,
    //         VestaEngine,
    //         RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
    //         RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
    //     >::new();
    //     let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark)
    //         = scheme.setup().unwrap();
    //     let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);
    //     let verification_keys = (&vk_r, &vk_zksnark);
    //
    //     // set blocklist and ban_over_signatures map
    //     let blocklist = scheme.initialize_blocklist().unwrap();
    //     let mut ban_over_signatures = HashMap::new();
    //
    //     // set user
    //     let last_block_for_register = blocklist.last().unwrap().clone();
    //     let (k, r_com, com_k, cold_start_block) =
    //         scheme.register_user1(last_block_for_register.clone()).unwrap();
    //     let sign_start =
    //         scheme.register_idp(sk_id.clone(), com_k.clone(), cold_start_block.clone(), blocklist.clone()).unwrap();
    //     let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();
    //
    //     // set message and token
    //     let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
    //     let token = scheme.extract_token(&cred, &msg1).unwrap();
    //
    //     let result = scheme.audit_blocklist(&pp, &msg1, &cred, &blocklist, &ban_over_signatures, public_keys, verification_keys);
    //
    //     assert!(result.clone().err().is_none());
    // }

    #[test]
    fn test_blocklist_add() {
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
        let public_keys = (pk_sp.clone(), pk_id, pk_r, pk_zksnark);

        // set blocklist and ban_over_signatures map
        let mut blocklist = scheme.initialize_blocklist().unwrap();

        // set user
        let last_block_for_register = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set message and token
        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token = scheme.extract_token(&cred, &msg1).unwrap();

        let result = scheme.add_token_to_blocklist(&token, &mut blocklist);
        assert!(result.err().is_none());
    }

    #[test]
    fn test_blocklist_remove() {
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
        let public_keys = (pk_sp, pk_id, pk_r, pk_zksnark);

        // set blocklist and ban_over_signatures map
        let mut blocklist = scheme.initialize_blocklist().unwrap();
        let mut ban_over_signatures = HashMap::new();

        // set user
        let last_block = blocklist.last().unwrap().clone();
        let (k, r_com, com_k) =
            scheme.register_user1().unwrap();
        let (cold_start_block, sign_start) =
            scheme.register_idp(sk_id.clone(), com_k.clone(), blocklist.clone()).unwrap();
        let cred = scheme.register_user2(k, r_com, &com_k, &cold_start_block, sign_start.clone()).unwrap();

        // set message and token that will be blocked
        let msg1 = <pallas::Scalar as Field>::random(rand::thread_rng());
        let token1 = scheme.extract_token(&cred, &msg1).unwrap();

        // add user's token to the blocklist
        blocklist = scheme.add_token_to_blocklist(&token1, &mut blocklist).unwrap().clone();

        let ban_over_block = blocklist.last().unwrap().clone();
        ban_over_signatures = scheme.remove_from_blocklist(ban_over_block, &sk_sp, &mut ban_over_signatures).unwrap().clone();

        assert_eq!(ban_over_signatures.len(), 1);
    }

    #[test]
    fn test_blocklist_digest() {
        let blocklisting_scheme = BlocklistingScheme::<
            PallasCurve,
            VestaCurve,
            PallasEngine,
            VestaEngine,
            RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
            RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
        >::new();
        let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark) = blocklisting_scheme.setup().unwrap();

        let blocklist = blocklisting_scheme.initialize_blocklist().unwrap();

        let digest = blocklisting_scheme.digest_blocklist(&blocklist);

        assert!(digest.err().is_none())
    }
}