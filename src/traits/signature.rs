use std::error::Error;

/// Trait representing a digital signature scheme.
pub trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;
    type Message;

    fn keygen() -> (Self::PublicKey, Self::SecretKey);

    fn sign(secret_key: &Self::SecretKey, message: &Self::Message) -> Result<Self::Signature, Box<dyn Error>>;

    fn verify(public_key: &Self::PublicKey, message: &Self::Message, signature: &Self::Signature) -> Result<bool, Box<dyn Error>>;
}