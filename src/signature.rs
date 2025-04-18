use std::error::Error;
use core::ops::{Add, Mul};
use std::marker::PhantomData;
use crate::traits::signature::SignatureScheme;
use crate::poseidon::poseidon_hash;
use crate::util::{DomainSeparator, rand_field};
use crate::curve::{PastaCurve, base_to_scalar};

pub struct SchnorrSignatureScheme<C: PastaCurve> {
    _p: PhantomData<C>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SchnorrSignature<C: PastaCurve> {
    pub R: C::Point,
    pub s: C::Scalar,
}

impl<C: PastaCurve> SignatureScheme for SchnorrSignatureScheme<C> {
    type PublicKey = C::Point;
    type SecretKey = C::Scalar;
    type Signature = SchnorrSignature<C>;
    type Message = Vec<C::Base>;

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        let g = C::generator();
        let private_key = rand_field::<C::Scalar>();
        let public_key = C::mul(&g, &private_key);
        (public_key, private_key)
    }

    fn sign(secret_key: &Self::SecretKey, message: &Self::Message) -> Result<Self::Signature, Box<dyn Error>> {
        let g = C::generator();
        let r = rand_field::<C::Scalar>();
        let gr = C::mul(&g, &r);

        let public_key = C::mul(&g, secret_key);
        let e: <C as PastaCurve>::Scalar = hash_of::<C>(&public_key, &gr, message.clone());

        let ex = e.mul(secret_key);
        let s = r.add(ex);

        Ok(SchnorrSignature { R: gr, s })
    }

    fn verify(public_key: &Self::PublicKey, message: &Self::Message, signature: &Self::Signature) -> Result<bool, Box<dyn Error>> {
        let g = C::generator();
        let e = hash_of::<C>(public_key, &signature.R, message.clone());

        let v1 = C::mul(&g, &signature.s); //v1 = g^s = g^{r+ex} where x = secret_key
        let v2 = C::add_points(&C::mul(&public_key, &e), &signature.R); //v2 = (g^x)^e * g^r = g^{r+ex}

        Ok(C::eq_points(&v1, &v2))
    }
}

fn hash_of<C: PastaCurve>(pk: &<C as PastaCurve>::Point, R: &<C as PastaCurve>::Point, message: Vec<<C as PastaCurve>::Base>) -> <C as PastaCurve>::Scalar {
    let (R_x, R_y) = C::to_affine(R);
    let (pk_x, pk_y) = C::to_affine(pk);

    let mut hash_messages = Vec::new();
    for m in message {
        hash_messages.push(m);
    }
    hash_messages.push(R_x);
    hash_messages.push(R_y);
    hash_messages.push(pk_x);
    hash_messages.push(pk_y);

    let h = poseidon_hash::<C::Base>(hash_messages, DomainSeparator::SIGNATURE.value());

    return base_to_scalar::<C>(h);
}


