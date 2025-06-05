class PyaktaError(Exception):
    """Base class for exceptions in the PyAkta library."""
    pass

class DIDResolutionError(PyaktaError):
    """Raised when a DID cannot be resolved."""
    pass

class SignatureError(PyaktaError):
    """Raised when there is an error with a cryptographic signature."""
    pass

class NormalizationError(PyaktaError):
    """Raised when there is an error during data normalization."""
    pass

class VCValidationError(PyaktaError):
    """Raised when a Verifiable Credential fails validation."""
    pass 