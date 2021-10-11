use core::fmt;

/// An error that occurs during certificate validation or name validation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    X509ParsingError,
    /// The certificate is not valid for the name it is being validated for.
    CertNotValidForName,
    /// The certificate violates one or more name constraints.
    NameConstraintViolation,
    /// The certificate violates one or more path length constraints.
    PathLenConstraintViolated,
    /// A valid issuer for the certificate could not be found.
    UnknownIssuer,
    /// OpenSSL Errors
    OpenSSLInvalid,
    OpenSSLFailed,
    /// Certificate either expired or not yet valid
    CertNotTimeValid,
    /// ACC Checks included in one or more certs failed
    ACCFailure,
    /// Certificate Revoked
    CertRevoked,
    /// Leaf validity period checks, mostly for Chrome
    LeafValidForTooLong,
    /// Some unkown Prolog failure
    UnknownError,
    ROOTSKIPPED,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self) }
}

#[cfg(feature = "std")]
impl ::std::error::Error for Error {}

