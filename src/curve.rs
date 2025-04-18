use std::fmt::Debug;
use std::ops::Mul;
use ff::{FieldBits, PrimeField, PrimeFieldBits, Field};
use pasta_curves::{pallas, vesta};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::group::{Curve, Group};
use serde::{Deserialize, Serialize};
use std::hash::Hash;

pub trait PastaCurve: PartialEq + Hash + Clone + Debug{ 
    type Point: Clone+Debug;
    type Scalar:  PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq + Clone;
    type Base: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq + Clone;

    fn generator() -> Self::Point;
    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point;
    fn add(scalar1: &Self::Scalar, scalar2: &Self::Scalar) -> Self::Scalar;
    fn add_points(point1: &Self::Point, point2: &Self::Point) -> Self::Point;
    fn to_affine(point: &Self::Point) -> (Self::Base, Self::Base);
    fn to_le_bits(point: &Self::Base) -> FieldBits<<Self::Base as PrimeFieldBits>::ReprBits>;
    fn eq_points(point1: &Self::Point, point2: &Self::Point) -> bool;
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub struct PallasCurve;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub struct VestaCurve;

impl PastaCurve for PallasCurve {
    type Point = pallas::Point;
    type Scalar = pallas::Scalar;
    type Base = pallas::Base;

    fn generator() -> Self::Point {
        pallas::Point::generator()
    }
    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point {
        point.mul(scalar)
    }
    fn add(scalar1: &Self::Scalar, scalar2: &Self::Scalar) -> Self::Scalar {
        scalar1.add(scalar2)
    }
    fn add_points(point1: &Self::Point, point2: &Self::Point) -> Self::Point {
        point1 + point2
    }
    fn to_affine(point: &Self::Point) -> (Self::Base, Self::Base) {
        (*point.to_affine().coordinates().unwrap().x(), *point.to_affine().coordinates().unwrap().y())
    }
    fn to_le_bits(point: &Self::Base) -> FieldBits<<Self::Base as PrimeFieldBits>::ReprBits> {
        point.to_le_bits()
    }
    fn eq_points(point1: &Self::Point, point2: &Self::Point) -> bool {
        point1 == point2
    }
}


impl PastaCurve for VestaCurve {
    type Point = vesta::Point;
    type Scalar = vesta::Scalar;
    type Base = vesta::Base;

    fn generator() -> Self::Point {
        vesta::Point::generator()
    }
    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point {
        point.mul(scalar)
    }
    fn add(scalar1: &Self::Scalar, scalar2: &Self::Scalar) -> Self::Scalar {
        scalar1.add(scalar2)
    }
    fn add_points(point1: &Self::Point, point2: &Self::Point) -> Self::Point {
        point1 + point2
    }
    fn to_affine(point: &Self::Point) -> (Self::Base, Self::Base) {
        (*point.to_affine().coordinates().unwrap().x(), *point.to_affine().coordinates().unwrap().y())
    }
    fn to_le_bits(base: &Self::Base) -> FieldBits<<Self::Base as PrimeFieldBits>::ReprBits> {
        base.to_le_bits()
    }
    fn eq_points(point1: &Self::Point, point2: &Self::Point) -> bool {
        point1 == point2
    }
}

pub fn base_to_scalar<C: PastaCurve>(input: <C as PastaCurve>::Base) -> <C as PastaCurve>::Scalar {
    let input_bits = input.to_le_bits();
    let mut mult = <C as PastaCurve>::Scalar::ONE;
    let mut val = <C as PastaCurve>::Scalar::ZERO;
    for bit in input_bits {
      if bit {
        val += mult;
      }
      mult = mult + mult;
    }
    val
}

pub fn scalar_to_base<C: PastaCurve>(input: <C as PastaCurve>::Scalar) -> <C as PastaCurve>::Base {
    let input_bits = input.to_le_bits();
    let mut val = <C as PastaCurve>::Base::ZERO;
    let mut mult = <C as PastaCurve>::Base::ONE;
    for bit in input_bits {
        if bit {
          val += mult;
        }
        mult = mult + mult;
      }
      val
  }

  
  pub fn field_to_int<F: PrimeFieldBits>(input: F) -> u64 {
    let input_bits = input.to_le_bits();
    let mut mult = 1;
    let mut val = 0;
    for bit in input_bits {
      if bit {
        val += mult;
      }
      mult = mult + mult;
    }
    val
}