use core::{fmt::Display, num::TryFromIntError};
use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub enum Error {
    CryptoCoreError(CryptoCoreError),
    ConversionFailed(String),
    LengthMismatch { expected: usize, got: usize },
    NonInvertible,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CryptoCoreError(err) => write!(f, "CryptoCore error{err}"),
            Self::ConversionFailed(err) => write!(f, "Conversion failed: {err}"),
            Self::NonInvertible => write!(
                f,
                "failed to invert R25519Scalar (x+e)=0 — resample e and retry"
            ),
            Self::LengthMismatch { expected, got } => {
                write!(f, "length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<CryptoCoreError> for Error {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCoreError(e)
    }
}

impl From<TryFromIntError> for Error {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}
