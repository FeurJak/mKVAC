use std::iter::Sum;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Deref;
use std::ops::Div;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Neg;
use std::ops::Sub;
use std::ops::SubAssign;

use super::errors::Error;
use super::traits::{Group, One, Ring, Sampling, Zero};

use cosmian_crypto_core::bytes_ser_de::Deserializer;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_crypto_core::bytes_ser_de::Serializer;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;

use cosmian_crypto_core::CryptoCoreError;
pub use cosmian_crypto_core::R25519PrivateKey as Scalar;
pub use cosmian_crypto_core::R25519PublicKey as EcPoint;
use tiny_keccak::Hasher;
use tiny_keccak::Sha3;
use zeroize::Zeroize;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as CurveScalar;

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct R25519Point(EcPoint);

impl R25519Point {
    pub fn generator() -> Self {
        Self(EcPoint::generator())
    }
}

impl Zero for R25519Point {
    fn zero() -> Self {
        Self(EcPoint::identity())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl Neg for R25519Point {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let p = CompressedRistretto(self.0.to_bytes()).decompress().unwrap();
        let neg = p.neg().compress().to_bytes();
        Self(EcPoint::try_from_bytes(neg).unwrap())
    }
}

impl Add for R25519Point {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl Add<&R25519Point> for R25519Point {
    type Output = Self;

    fn add(self, rhs: &R25519Point) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl Add<&R25519Point> for &R25519Point {
    type Output = R25519Point;

    fn add(self, rhs: &R25519Point) -> Self::Output {
        R25519Point(&self.0 + &rhs.0)
    }
}

impl AddAssign for R25519Point {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = &self.0 + &rhs.0;
    }
}

impl Sub for R25519Point {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl SubAssign for R25519Point {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = &self.0 - &rhs.0
    }
}

impl Sub<&R25519Point> for R25519Point {
    type Output = Self;

    fn sub(self, rhs: &R25519Point) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl Sub<&R25519Point> for &R25519Point {
    type Output = R25519Point;

    fn sub(self, rhs: &R25519Point) -> Self::Output {
        R25519Point(&self.0 - &rhs.0)
    }
}

impl Group for R25519Point {}

impl Serializable for R25519Point {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.0.write(ser).map_err(Self::Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self).map_err(Self::Error::from)
    }
}

impl Sum for R25519Point {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, p| a + p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct R25519Scalar(Scalar);

impl R25519Scalar {
    pub fn inverse(&self) -> Result<R25519Scalar, Error> {
        let s = CurveScalar::from_canonical_bytes(self.0.to_bytes());
        let inverse = Scalar::try_from_bytes(s.unwrap().invert().to_bytes())?;
        Ok(Self(inverse))
    }
}

impl Deref for R25519Scalar {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_bytes()
    }
}

impl Zero for R25519Scalar {
    fn zero() -> Self {
        Self(Scalar::zero())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl One for R25519Scalar {
    fn one() -> Self {
        Self(Scalar::one())
    }

    fn is_one(&self) -> bool {
        self == &Self::one()
    }
}

impl Add for R25519Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for R25519Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = &self.0 + &rhs.0;
    }
}

impl Add<&R25519Scalar> for R25519Scalar {
    type Output = Self;

    fn add(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 + &rhs.0)
    }
}

impl Add<&R25519Scalar> for &R25519Scalar {
    type Output = R25519Scalar;

    fn add(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Scalar(&self.0 + &rhs.0)
    }
}

impl Sub for R25519Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl SubAssign for R25519Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = &self.0 - &rhs.0
    }
}

impl Sub<&R25519Scalar> for R25519Scalar {
    type Output = Self;

    fn sub(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl Sub<&R25519Scalar> for &R25519Scalar {
    type Output = R25519Scalar;

    fn sub(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Scalar(&self.0 - &rhs.0)
    }
}

impl Mul for R25519Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl MulAssign for R25519Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = &self.0 * &rhs.0
    }
}

impl Mul<&R25519Scalar> for R25519Scalar {
    type Output = Self;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl Mul<&R25519Scalar> for &R25519Scalar {
    type Output = R25519Scalar;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Scalar(&self.0 * &rhs.0)
    }
}

impl Div for R25519Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl Div<&R25519Scalar> for R25519Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: &R25519Scalar) -> Self::Output {
        &self / rhs
    }
}

impl Div<&R25519Scalar> for &R25519Scalar {
    type Output = Result<R25519Scalar, CryptoCoreError>;

    fn div(self, rhs: &R25519Scalar) -> Self::Output {
        (&self.0 / &rhs.0).map(R25519Scalar)
    }
}

impl Sum for R25519Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, s| a + s)
    }
}

impl Group for R25519Scalar {}

impl Ring for R25519Scalar {
    type DivError = CryptoCoreError;
}

impl Serializable for R25519Scalar {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.0.write(ser).map_err(Self::Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self).map_err(Self::Error::from)
    }
}

impl Sampling for R25519Scalar {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Scalar::new(rng))
    }

    fn hash(seed: &[u8]) -> Self {
        let mut hasher = Sha3::v512();
        let mut bytes = [0; 512 / 8];
        hasher.update(seed);
        hasher.finalize(&mut bytes);
        let s = Self(Scalar::from_raw_bytes(&bytes));
        bytes.zeroize();
        s
    }
}

impl From<&[u8; 64]> for R25519Scalar {
    fn from(bytes: &[u8; 64]) -> Self {
        Self(Scalar::from_raw_bytes(&bytes))
    }
}

impl From<u64> for R25519Scalar {
    fn from(u: u64) -> Self {
        let s = CurveScalar::from(u).to_bytes();
        Self(Scalar::try_from_bytes(s).unwrap())
    }
}

impl From<&R25519Scalar> for R25519Point {
    fn from(s: &R25519Scalar) -> Self {
        Self(EcPoint::from(&s.0))
    }
}

impl Mul<R25519Scalar> for R25519Point {
    type Output = Self;

    fn mul(self, rhs: R25519Scalar) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl MulAssign<R25519Scalar> for R25519Point {
    fn mul_assign(&mut self, rhs: R25519Scalar) {
        self.0 = &self.0 * &rhs.0
    }
}

impl Mul<&R25519Scalar> for R25519Point {
    type Output = Self;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl Mul<&R25519Scalar> for &R25519Point {
    type Output = R25519Point;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Point(&self.0 * &rhs.0)
    }
}
