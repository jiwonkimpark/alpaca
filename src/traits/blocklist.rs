use crate::errors::AnonymousBlocklistError;

pub trait AnonymousBlocklistingScheme {
    type PublicParams;
    type PublicKey;
    type SecretKey;
    type ProverKey;
    type VerifierKey;
    type TagNonce;
    type Cred;
    type K;
    type Random;
    type AuthToken;
    type Block;
    type Message;
    type Blocklist;
    type SyncProof;
    type UpdatableSyncProof;
    type UpdatableSyncStatus;
    type AuthProof;
    type VerificationKey;
    type Commitment;
    type Signature;
    type HashValue;
    type BanOverSignatures;
    type Digest;
    type IvcPrimaryCircuit;
    type IvcSecondaryCircuit;

    fn new() -> Self;

    fn setup(&self) -> Result<(Self::PublicParams, Self::PublicKey, Self::PublicKey, Self::PublicKey, Self::ProverKey, Self::SecretKey, Self::SecretKey, Self::VerificationKey, Self::VerifierKey), AnonymousBlocklistError>;

    fn default_circuit(&self, pk_id: &Self::PublicKey, sk_id: &Self::SecretKey, pk_sp: &Self::PublicKey) -> Self::IvcPrimaryCircuit;

    fn register_user1(&self) -> Result<(Self::K, Self::Random, Self::Commitment), AnonymousBlocklistError>;

    fn register_user2(&self, k: Self::K, r: Self::Random, com_k: &Self::Commitment, b_start: &Self::Block, sig: Self::Signature) -> Result<Self::Cred, AnonymousBlocklistError>;

    fn register_idp(&self, sk_id: Self::SecretKey, com_k: Self::Commitment, blocklist: Self::Blocklist) -> Result<(Self::Block, Self::Signature), AnonymousBlocklistError>;

    fn extract_token(&self, cred: &Self::Cred, message: &Self::Message) -> Result<Self::AuthToken, AnonymousBlocklistError>;

    fn initialize_blocklist(&self) -> Result<Self::Blocklist, AnonymousBlocklistError>;

    fn add_token_to_blocklist<'a>(&'a self, token: &Self::AuthToken, blocklist: &'a mut Self::Blocklist) -> Result<&mut Self::Blocklist, AnonymousBlocklistError>;

    fn remove_from_blocklist<'a>(&'a self, block: Self::Block, sk_sp: &Self::SecretKey, ban_over_signatures: &'a mut Self::BanOverSignatures) -> Result<&mut Self::BanOverSignatures, AnonymousBlocklistError>;

    fn digest_blocklist(&self, blocklist: &Self::Blocklist) -> Result<Self::Digest, AnonymousBlocklistError>;

    // fn audit_blocklist(&self, pp: &Self::PublicParams, message: &Self::Message, cred: &Self::Cred, blocklist: &Self::Blocklist, ban_over_signatures: &Self::BanOverSignatures, public_keys: (&Self::PublicKey, &Self::PublicKey, &Self::PublicKey, &Self::ProverKey), verification_key: (&Self::VerificationKey, &Self::VerifierKey)) -> Result<bool, AnonymousBlocklistError>;

    fn rerandomize_usync_proof(&self, pp: &Self::PublicParams, pk_id: &Self::PublicKey, pk_sp: &Self::PublicKey, cred: &Self::Cred, usync_proof_l: Option<Self::UpdatableSyncProof>, usync_status_l: Option<Self::UpdatableSyncStatus>, ) -> Result<(Self::UpdatableSyncProof, Self::UpdatableSyncStatus), AnonymousBlocklistError>;

    fn updatable_synchronize(&self, pp: &Self::PublicParams, pk_id: &Self::PublicKey, pk_sp: &Self::PublicKey, b_j: &Self::Block, b_j_minus_1: Option<&Self::Block>, sign_ban_over: Option<&Self::Signature>, cred: &Self::Cred, usync_proof_i: Option<Self::UpdatableSyncProof>, usync_status_i: Option<Self::UpdatableSyncStatus>) -> Result<(Self::UpdatableSyncProof, Self::UpdatableSyncStatus), AnonymousBlocklistError>;

    fn synchronize(&self, pp: &Self::PublicParams, pk_id: &Self::PublicKey, pk_sp: &Self::PublicKey, blocklist: &Self::Blocklist, ban_over_signatures: &Self::BanOverSignatures, cred: &Self::Cred, usync_proof_i: Option<Self::UpdatableSyncProof>, usync_status_i: Option<Self::UpdatableSyncStatus>) -> Result<(Option<Self::UpdatableSyncProof>, Option<Self::UpdatableSyncStatus>), AnonymousBlocklistError>;

    fn authorize_token(&self, pp: &Self::PublicParams, token: &Self::AuthToken, cred: &Self::Cred, public_keys: (&Self::PublicKey, &Self::PublicKey, &Self::PublicKey, &Self::ProverKey), usync_proof_l: Option<Self::UpdatableSyncProof>, usync_status_l: Option<Self::UpdatableSyncStatus>) -> Result<Self::AuthProof, AnonymousBlocklistError>;

    fn verify_auth_proof(&self, token: &Self::AuthToken, message: &Self::Message, digest: Self::Digest, pk_id: &Self::PublicKey, pk_sp: &Self::PublicKey, ver_keys: (&Self::VerificationKey, &Self::VerifierKey), auth_proof: &Self::AuthProof) -> Result<bool, AnonymousBlocklistError>;

    fn f(&self, h_j: &Self::HashValue, com_k_i: &Self::Commitment, pk_id: &Self::PublicKey, pk_sp: &Self::PublicKey, cred: &Self::Cred, sign_ban_over_j: Option<&Self::Signature>, b_j: Option<&Self::Block>, b_j_minus_1: Option<&Self::Block>, r_i: &Self::Random, r_i_plus_1: &Self::Random) -> Result<(Self::Commitment, Self::HashValue), AnonymousBlocklistError>;
}