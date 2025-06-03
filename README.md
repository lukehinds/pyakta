# pyakta

[![PyPI version](https://badge.fury.io/py/pyakta.svg)](https://badge.fury.io/py/pyakta)

**Python library for Akta.**

Akta is a system designed to enable secure and verifiable interactions between AI agents. It establishes a robust framework for capability-based access control, allowing agents to confidently delegate tasks and share resources with fine-grained control. The system leverages concepts from Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) to create a cryptographically secure and auditable environment for autonomous agent operations.

**Important Note:** *Akta is currently a prototype. The codebase has not undergone a third-party security audit and is not yet considered suitable for production environments. Development will move fast, expect breaking changes, bugs, and other issues.*

## Features

*   Capability-based access control using Verifiable Credentials.
*   Generation and management of Decentralized Identifiers (`did:key` and `did:web` methods).
*   Creation, signing, and verification of W3C Verifiable Credentials using Ed25519Signature2020.
*   Pydantic models for core data structures (VCs, DIDs, Proofs).
*   Cryptographically secure operations leveraging PyNaCl.
*   JSON-LD processing for credential normalization.

## Requirements

*   Python 3.11+
*   `base58>=2.1.1`
*   `pynacl>=1.5.0`
*   `pydantic>=2.11.0`
*   `pyld>=2.0.4`

## Installation

You can install `pyakta` in a few ways:

**From PyPI:**

```bash
pip install pyakta
```

**From Source:**

```bash
git clone https://github.com/lukehinds/pyakta.git
cd pyakta
```

## Usage

Here's a basic example of how to generate a DID and create/sign a Verifiable Credential:

```python
from pyakta.did import DIDKey
from pyakta.credentials import VerifiableCredential
from datetime import datetime, timedelta, UTC # Make sure UTC is imported

# 1. Generate an issuer DID (did:key method)
issuer_did_key = DIDKey()
print(f"Issuer DID: {issuer_did_key.did}")
print(f"Issuer Public Key (Multibase): {issuer_did_key.public_key_multibase}")

# 2. Define subject and credential details
subject_did_str = "did:example:subject123"
now = datetime.now(UTC)

# 3. Build the Verifiable Credential
vc = VerifiableCredential().build(
    issuer_did=issuer_did_key.did,
    subject_did=subject_did_str,
    types=["VerifiableCredential", "AgentAccessCredential"],
    issuance_date=now,
    expiration_date=now + timedelta(days=30),
    credential_subject={
        "id": subject_did_str,
        "serviceEndpoint": "https://example.com/agent/service",
        "actions": ["read", "write"]
    }
)

# 4. Sign the Verifiable Credential
# The verification method ID for did:key is typically the DID itself + # + public key multibase
verification_method = f"{issuer_did_key.did}#{issuer_did_key.public_key_multibase}"
vc.sign(
    issuer_signing_key=issuer_did_key.signing_key,
    verification_method_id=verification_method
)

print("\nSigned Verifiable Credential:")
print(vc.to_json(indent=2))

# 5. Verify the Verifiable Credential
is_valid = vc.verify_signature(
    issuer_public_key=issuer_did_key.verify_key,
    expected_issuer_did=issuer_did_key.did,
    expected_subject_did=subject_did_str
)
print(f"\nVC Signature Valid: {is_valid}")

# Check expiration
print(f"VC Expired: {vc.is_expired()}")
```

This example demonstrates:
- Generating a `did:key`.
- Building a `VerifiableCredential` with specific subject data, type, issuance, and expiration.
- Signing the credential using the issuer's signing key.
- Verifying the credential's signature.

## Running Tests

Tests are managed using `pytest`. To run the tests:

1.  Ensure you have the development dependencies installed:
    ```bash
    pip install -e ".[dev]"
    # or if using PDM:
    # pdm install -G dev
    ```
2.  Navigate to the root of the project and run:
    ```bash
    pytest
    ```
    Or, if you have a `Makefile` with a test target (as indicated by your test output):
    ```bash
    make test
    ```
This will discover and run all tests in the `pyakta/tests` directory and provide a coverage report.

## Contributing

We honestly love getting contributions, from engineers of all levels and background!

Don't be put off contributing, we're all learning as we go and everyone starts
somewhere.

You could always look for good first issues to get started, and tag me in the PR
(@lukehinds) and I am happy to give you plently of friendly support and guidance (if you want it).

## License

This project is licensed under the Apache 2.0 License - see the `LICENSE` file for details.