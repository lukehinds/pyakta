import unittest
import json
from datetime import datetime, timedelta
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError
from pydantic import ValidationError

from pyld import jsonld

try:
    from pyld import jsonld_requests  # For the requests document loader

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from pyakta.credentials import VerifiableCredential
from pyakta.models import UTC  # Assuming UTC is defined in models
from pyakta.exceptions import (
    PyaktaError,
    SignatureError,
    NormalizationError,
    VCValidationError,
)

# --- JSON-LD Context Handling for Tests ---
# Minimal cache for essential contexts to avoid network calls during tests
# These are simplified; for full validation, you might need the complete contexts.
CACHED_CONTEXTS = {
    "https://www.w3.org/2018/credentials/v1": {
        "@context": {
            "id": "@id",
            "type": "@type",
            "VerifiableCredential": {
                "@id": "https://www.w3.org/2018/credentials#VerifiableCredential"
            },
            "credentialSubject": {
                "@id": "https://www.w3.org/2018/credentials#credentialSubject"
            },
            "issuer": {
                "@id": "https://www.w3.org/2018/credentials#issuer",
                "@type": "@id",
            },
            "issuanceDate": {
                "@id": "https://www.w3.org/2018/credentials#issuanceDate",
                "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
            },
            "expirationDate": {
                "@id": "https://www.w3.org/2018/credentials#expirationDate",
                "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
            },
            "proof": {"@id": "https://w3id.org/security#proof"},
        }
    },
    "https://w3id.org/security/suites/ed25519-2020/v1": {
        "@context": {
            "id": "@id",
            "type": "@type",
            "Ed25519Signature2020": {
                "@id": "https://w3id.org/security#Ed25519Signature2020"
            },
            "created": {
                "@id": "http://purl.org/dc/terms/created",
                "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
            },
            "proofPurpose": {
                "@id": "https://w3id.org/security#proofPurpose"
            },  # @type @vocab is common
            "proofValue": {
                "@id": "https://w3id.org/security#proofValue"
            },  # No specific type needed for string here usually
            "verificationMethod": {
                "@id": "https://w3id.org/security#verificationMethod",
                "@type": "@id",
            },
        }
    },
    # Placeholder for other contexts if they were meant to be dereferenceable
    "https://example.org/context": {
        "@context": {"customClaim": "https://example.org/customClaim"}
    },
    "https://example.com/context/v1": {  # from test_vc_model_creation_with_all_fields (via full_vc_data in test_models.py, but here for credentials)
        "@context": {"customField": "https://example.com/customField"}
    },
    "https://example.com/context/v2": {  # from test_from_dict_handles_context_alias
        "@context": {"anotherField": "https://example.com/anotherField"}
    },
}


def _custom_document_loader(url, options=None):
    if url in CACHED_CONTEXTS:
        return {
            "contextUrl": None,
            "documentUrl": url,
            "document": CACHED_CONTEXTS[url],
        }

    # If requests is available and URL not in cache, try to fetch it
    # This provides a fallback if a new, uncached context URL is used in tests.
    if HAS_REQUESTS:
        try:
            # Ensure options exist if the loader expects it
            return jsonld_requests.requests_document_loader()(
                url, options if options else {}
            )
        except Exception as e:
            raise jsonld.JsonLdError(
                f"Failed to load remote context '{url}' using requests_document_loader.",
                "loading.document.failed",
                details=str(e),
                code="loading document failed",
            )

    # Fallback if no specific handling and requests is not available or failed for an un-cached URL
    raise jsonld.JsonLdError(
        f"URL '{url}' could not be dereferenced: not found in cache and no suitable HTTP loader available/successful.",
        "loading.document.failed",  # Standard error code
        {"url": url},
        code="loading document failed",  # General code for this type of error
    )


# Set the custom loader globally for pyld for the duration of these tests
jsonld.set_document_loader(_custom_document_loader)

# Helper to generate keys (in a real scenario, you might load them or use a fixture)
SIGNING_KEY = SigningKey.generate()
VERIFY_KEY = SIGNING_KEY.verify_key
VERIFICATION_METHOD_ID = "did:example:issuer1#keys-1"


class TestVerifiableCredential(unittest.TestCase):
    def setUp(self):
        self.issuer_did = "did:example:issuer1"
        self.subject_did = "did:example:subject1"
        self.credential_subject_data = {
            "id": self.subject_did,
            "alumniOf": "Example University",
        }
        self.now = datetime.now(UTC)

    def test_vc_init_empty(self):
        vc = VerifiableCredential()
        self.assertIsNone(vc.model)

    def test_vc_init_with_valid_data(self):
        vc_data = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "urn:uuid:some-id",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": self.now.isoformat().replace(
                "+00:00", "Z"
            ),  # Pydantic expects str here
            "credentialSubject": self.credential_subject_data,
        }
        vc = VerifiableCredential(data=vc_data)
        self.assertIsNotNone(vc.model)
        self.assertEqual(vc.id, "urn:uuid:some-id")
        self.assertEqual(vc.issuer_did, self.issuer_did)

    def test_vc_init_with_invalid_data(self):
        invalid_vc_data = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "urn:uuid:some-id",
            # Missing 'type', 'issuer', etc.
        }
        with self.assertRaises(VCValidationError):
            VerifiableCredential(data=invalid_vc_data)

    def test_vc_build_minimal(self):
        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did, subject_did=self.subject_did
        )
        self.assertIsNotNone(vc.model)
        self.assertTrue(vc.id.startswith("urn:uuid:"))
        self.assertEqual(vc.issuer_did, self.issuer_did)
        self.assertEqual(vc.subject_did, self.subject_did)
        self.assertEqual(vc.model.type, VerifiableCredential.DEFAULT_TYPE)
        self.assertLessEqual(
            vc.model.issuanceDate, datetime.now(UTC)
        )  # Should be close to now
        self.assertEqual(vc.model.credentialSubject, {"id": self.subject_did})

    def test_vc_build_full(self):
        custom_id = "urn:custom:123"
        custom_types = ["VerifiableCredential", "CustomType"]
        custom_context = [
            "https://www.w3.org/2018/credentials/v1",
            "https://example.org/context",
        ]
        issuance = self.now - timedelta(days=1)
        expiration = self.now + timedelta(days=30)
        custom_cs = {"id": self.subject_did, "customClaim": "value"}

        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            credential_id=custom_id,
            types=custom_types,
            contexts=custom_context,
            issuance_date=issuance,
            expiration_date=expiration,
            credential_subject=custom_cs,
        )
        self.assertEqual(vc.id, custom_id)
        self.assertEqual(vc.model.type, custom_types)
        self.assertEqual(vc.model.context, custom_context)
        self.assertEqual(vc.issuance_date, issuance)
        self.assertEqual(vc.expiration_date, expiration)
        self.assertEqual(vc.model.credentialSubject, custom_cs)

    def test_sign_and_verify_successful(self):
        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            credential_subject=self.credential_subject_data,
        )
        vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)
        self.assertIsNotNone(vc.proof)
        self.assertEqual(vc.proof.type, "Ed25519Signature2020")
        self.assertEqual(vc.proof.verificationMethod, VERIFICATION_METHOD_ID)
        self.assertEqual(vc.proof.proofPurpose, "assertionMethod")

        is_valid = vc.verify_signature(
            VERIFY_KEY,
            expected_issuer_did=self.issuer_did,
            expected_subject_did=self.subject_did,
        )
        self.assertTrue(
            is_valid, "Signature verification failed when it should succeed."
        )

    def test_verify_fails_with_wrong_key(self):
        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did, subject_did=self.subject_did
        )
        vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)

        wrong_signing_key = SigningKey.generate()
        wrong_verify_key = wrong_signing_key.verify_key
        with self.assertRaisesRegex(SignatureError, "Invalid LDP signature"):
            vc.verify_signature(wrong_verify_key)

    def test_verify_fails_if_vc_tampered_after_signing(self):
        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did, subject_did=self.subject_did
        )
        vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)

        # Tamper with a known field in the VC model directly after signing
        original_subject_id = vc.model.credentialSubject.get("id")
        vc.model.credentialSubject["id"] = str(original_subject_id) + "-tampered"

        with self.assertRaisesRegex(SignatureError, "Invalid LDP signature"):
            vc.verify_signature(VERIFY_KEY)

    def test_verify_fails_if_proof_tampered(self):
        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did, subject_did=self.subject_did
        )
        vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)

        # Tamper proof
        original_proof_value = vc.model.proof.proofValue
        vc.model.proof.proofValue = original_proof_value.replace("A", "B")
        
        with self.assertRaisesRegex(SignatureError, "Error decoding base58 proofValue|Invalid LDP signature"):
             vc.verify_signature(VERIFY_KEY)

        # Tamper proof type
        vc.model.proof.proofValue = original_proof_value
        vc.model.proof.type = "SomeOtherSignatureType"
        with self.assertRaisesRegex(SignatureError, "Invalid LDP signature"):
             vc.verify_signature(VERIFY_KEY)

    def test_sign_requires_built_model(self):
        vc = VerifiableCredential()
        with self.assertRaisesRegex(PyaktaError, "VC data model must be built or loaded before signing."):
            vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)

    def test_verify_requires_model_and_proof(self):
        vc_built = VerifiableCredential().build(issuer_did="d", subject_did="s")
        with self.assertRaisesRegex(VCValidationError, "VC model, proof, or proof.proofValue is missing"):
            vc_built.verify_signature(VERIFY_KEY)

        vc_built.model.proof = None
        with self.assertRaisesRegex(VCValidationError, "VC model, proof, or proof.proofValue is missing"):
            vc_built.verify_signature(VERIFY_KEY)
        
        vc_built.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)
        vc_built.model.proof.proofValue = None
        with self.assertRaisesRegex(VCValidationError, "VC model, proof, or proof.proofValue is missing"):
            vc_built.verify_signature(VERIFY_KEY)

    def test_properties_access(self):
        vc = VerifiableCredential()
        self.assertIsNone(vc.id)
        self.assertIsNone(vc.issuer_did)
        self.assertIsNone(vc.subject_did)
        self.assertIsNone(vc.expiration_date)
        self.assertIsNone(vc.issuance_date)
        self.assertIsNone(vc.proof)

        built_vc = vc.build(
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            expiration_date=self.now + timedelta(days=1),
        )
        self.assertIsNotNone(built_vc.id)
        self.assertEqual(built_vc.issuer_did, self.issuer_did)
        self.assertEqual(built_vc.subject_did, self.subject_did)
        self.assertIsNotNone(built_vc.expiration_date)
        self.assertIsNotNone(built_vc.issuance_date)
        self.assertIsNone(built_vc.proof)  # Before signing

        built_vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)
        self.assertIsNotNone(built_vc.proof)

        self.assertFalse(built_vc.is_expired(), "VC should not be expired yet.")

    def test_to_dict_and_to_json(self):
        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did, subject_did=self.subject_did
        )
        vc_dict = vc.to_dict()

        self.assertIn("@context", vc_dict)
        self.assertEqual(vc_dict["id"], vc.id)
        self.assertEqual(vc_dict["issuer"], self.issuer_did)

        vc_json = vc.to_json()
        vc_from_json_loaded = json.loads(vc_json)
        self.assertEqual(vc_from_json_loaded["id"], vc.id)

        # Test on uninitialized model
        empty_vc = VerifiableCredential()
        with self.assertRaisesRegex(PyaktaError, "VC model is not initialized."):
            empty_vc.to_dict()
        with self.assertRaisesRegex(PyaktaError, "VC model is not initialized."):
            empty_vc.to_json()

    def test_from_dict_and_from_json(self):
        original_vc_data = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:uuid:test-from-dict",
            "type": ["VerifiableCredential", "TestCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": self.now.isoformat().replace("+00:00", "Z"),
            "credentialSubject": {"id": self.subject_did, "key": "value"},
        }

        # Test from_dict
        vc_from_dict = VerifiableCredential.from_dict(original_vc_data)
        self.assertEqual(vc_from_dict.id, original_vc_data["id"])
        self.assertEqual(vc_from_dict.issuer_did, original_vc_data["issuer"])
        self.assertIsInstance(vc_from_dict.model.issuanceDate, datetime)

        # Test from_json
        vc_json_str = json.dumps(original_vc_data)
        vc_from_json = VerifiableCredential.from_json(vc_json_str)
        self.assertEqual(vc_from_json.id, original_vc_data["id"])
        self.assertEqual(vc_from_json.issuer_did, original_vc_data["issuer"])

    def test_from_dict_handles_context_alias(self):
        vc_data_alias = {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://example.com/context/v2"],
            "id": "urn:uuid:alias-test",
            "type": ["VerifiableCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": self.now.isoformat().replace("+00:00", "Z"),
            "credentialSubject": {"id": self.subject_did, "anotherField": "value"}
        }
        vc = VerifiableCredential.from_dict(vc_data_alias)
        self.assertIsNotNone(vc.model)
        self.assertEqual(vc.id, "urn:uuid:alias-test")
        self.assertIn("https://example.com/context/v2", vc.model.context)

    def test_from_invalid_dict_json(self):
        invalid_data_missing_fields = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "urn:uuid:invalid-1"
            # Missing type, issuer, issuanceDate, credentialSubject
        }
        with self.assertRaises(VCValidationError):
            VerifiableCredential.from_dict(invalid_data_missing_fields)
        
        invalid_json_string = '{"@context": [], "id": "test", }' # Trailing comma, invalid JSON
        with self.assertRaises(PyaktaError):
            VerifiableCredential.from_json(invalid_json_string)

        malformed_json_for_pydantic = '{"@context": ["https://www.w3.org/2018/credentials/v1"], "id": 12345, "type": ["Test"], "issuer": {}, "issuanceDate": "nodate", "credentialSubject": {}}'
        with self.assertRaises(VCValidationError):
            VerifiableCredential.from_json(malformed_json_for_pydantic)

    def test_verification_with_expected_dids(self):
        vc = VerifiableCredential().build(
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            credential_subject=self.credential_subject_data,
        )
        vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)

        self.assertTrue(vc.verify_signature(VERIFY_KEY, self.issuer_did, self.subject_did))

        with self.assertRaisesRegex(VCValidationError, "Issuer DID mismatch"):
            vc.verify_signature(VERIFY_KEY, "did:example:wrongissuer", self.subject_did)

        with self.assertRaisesRegex(VCValidationError, "Subject DID mismatch"):
            vc.verify_signature(VERIFY_KEY, self.issuer_did, "did:example:wrongsubject")

        with self.assertRaisesRegex(VCValidationError, "Issuer DID mismatch"):
            vc.verify_signature(VERIFY_KEY, "did:example:wrongissuer", "did:example:wrongsubject")

    def test_normalization_failure_during_sign(self):
        vc = VerifiableCredential().build(issuer_did=self.issuer_did, subject_did=self.subject_did)
        
        original_normalize = jsonld.normalize
        def mock_normalize_fail(*args, **kwargs):
            raise Exception("Simulated normalization crash")
        jsonld.normalize = mock_normalize_fail

        with self.assertRaisesRegex(NormalizationError, "JSON-LD Normalization failed: Simulated normalization crash"):
            vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)
        
        jsonld.normalize = original_normalize

    def test_normalization_failure_during_verify(self):
        vc = VerifiableCredential().build(issuer_did=self.issuer_did, subject_did=self.subject_did)
        vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)

        original_normalize = jsonld.normalize
        def mock_normalize_fail(*args, **kwargs):
            raise Exception("Simulated normalization crash for verify")
        jsonld.normalize = mock_normalize_fail

        with self.assertRaisesRegex(NormalizationError, "Error during JSON-LD normalization for verification: Simulated normalization crash for verify"):
            vc.verify_signature(VERIFY_KEY)
        
        jsonld.normalize = original_normalize

    def test_bad_signature_exception_is_signature_error(self):
        vc = VerifiableCredential().build(issuer_did=self.issuer_did, subject_did=self.subject_did)
        vc.sign(SIGNING_KEY, VERIFICATION_METHOD_ID)
        
        if vc.model and vc.model.proof and vc.model.proof.proofValue:
            tampered_proof_value = list(vc.model.proof.proofValue)
            tampered_proof_value[5] = 'B' if tampered_proof_value[5] != 'B' else 'C' 
            vc.model.proof.proofValue = "".join(tampered_proof_value)

            with self.assertRaises(SignatureError) as cm:
                vc.verify_signature(VERIFY_KEY)
        else:
            self.fail("VC proof or proofValue not found for tampering")


if __name__ == "__main__":
    unittest.main()
