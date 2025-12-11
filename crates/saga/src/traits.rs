use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Div;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Sub;
use std::ops::SubAssign;

pub trait Group:
    Sized
    + Zero
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
}

pub trait Sampling {
    fn random(rng: &mut impl CryptoRngCore) -> Self;
    fn hash(seed: &[u8]) -> Self;
}

pub trait Zero {
    fn zero() -> Self;
    fn is_zero(&self) -> bool;
}

pub trait One {
    fn one() -> Self;
    fn is_one(&self) -> bool;
}

pub trait Ring:
    Group
    + Zero
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Result<Self, Self::DivError>>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Result<Self, Self::DivError>>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Mul<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Div<&'b Self, Output = Result<Self, Self::DivError>>,
{
    type DivError;
}
