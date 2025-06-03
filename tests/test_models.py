import unittest
from datetime import datetime
from pydantic import ValidationError

from pyakta.models import ProofModel, VerifiableCredentialModel, UTC


class TestProofModel(unittest.TestCase):
    def test_proof_model_creation(self):
        created_time = datetime.now(UTC)
        proof_data = {
            "type": "Ed25519Signature2020",
            "created": created_time,
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:example:123#keys-1",
            "proofValue": "z123...",
        }
        proof = ProofModel(**proof_data)
        self.assertEqual(proof.type, "Ed25519Signature2020")
        self.assertEqual(proof.created, created_time)
        self.assertEqual(proof.proofPurpose, "assertionMethod")
        self.assertEqual(proof.verificationMethod, "did:example:123#keys-1")
        self.assertEqual(proof.proofValue, "z123...")

    def test_proof_model_datetime_serialization(self):
        created_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=UTC)
        proof = ProofModel(
            created=created_time,
            proofPurpose="assertionMethod",
            verificationMethod="did:example:123#keys-1",
            proofValue="z123...",
        )
        # Pydantic v2 model_dump_json, then parse
        import json

        proof_json = proof.model_dump_json()
        proof_dict_serialized = json.loads(proof_json)
        self.assertEqual(proof_dict_serialized["created"], "2023-01-01T12:00:00Z")

    def test_proof_model_missing_fields(self):
        with self.assertRaises(ValidationError):
            ProofModel(
                proofPurpose="assertionMethod"
            )  # Missing created, verificationMethod, proofValue


class TestVerifiableCredentialModel(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(UTC)
        self.credential_subject_data = {
            "id": "did:example:subject",
            "degree": {"type": "Bachelor", "name": "Science"},
        }
        self.minimal_vc_data = {
            "id": "urn:uuid:test-id",
            "type": ["VerifiableCredential", "TestCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": self.now,
            "credentialSubject": self.credential_subject_data,
        }

    def test_vc_model_creation_minimal(self):
        vc = VerifiableCredentialModel(**self.minimal_vc_data)
        self.assertEqual(vc.id, "urn:uuid:test-id")
        self.assertEqual(vc.type, ["VerifiableCredential", "TestCredential"])
        self.assertEqual(vc.issuer, "did:example:issuer")
        self.assertEqual(vc.issuanceDate, self.now)
        self.assertEqual(vc.credentialSubject, self.credential_subject_data)
        self.assertIsNone(vc.expirationDate)
        self.assertIsNone(vc.proof)
        # Check default context
        self.assertEqual(
            vc.context,
            [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
        )

    def test_vc_model_creation_with_all_fields(self):
        expiration = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)
        proof_data_obj = ProofModel(
            created=self.now,
            proofPurpose="assertionMethod",
            verificationMethod="did:example:issuer#key-1",
            proofValue="zProofValue",
        )
        full_vc_data = {
            **self.minimal_vc_data,
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://example.com/context/v1",
            ],
            "expirationDate": expiration,
            "proof": proof_data_obj,
        }
        vc = VerifiableCredentialModel(**full_vc_data)
        self.assertEqual(
            vc.context,
            [
                "https://www.w3.org/2018/credentials/v1",
                "https://example.com/context/v1",
            ],
        )
        self.assertEqual(vc.expirationDate, expiration)
        self.assertEqual(vc.proof, proof_data_obj)

    def test_vc_model_context_alias(self):
        vc_data_with_at_context = {
            "@context": "https://www.w3.org/2018/credentials/v1",
            **self.minimal_vc_data,
        }
        vc = VerifiableCredentialModel(**vc_data_with_at_context)
        self.assertEqual(vc.context, "https://www.w3.org/2018/credentials/v1")

        # Test serialization includes "@context"
        import json

        vc_json = vc.model_dump_json(by_alias=True)
        vc_dict_serialized = json.loads(vc_json)
        self.assertIn("@context", vc_dict_serialized)
        self.assertEqual(
            vc_dict_serialized["@context"], "https://www.w3.org/2018/credentials/v1"
        )

    def test_vc_model_datetime_serialization(self):
        issuance_date = datetime(2023, 1, 1, 12, 0, 0, tzinfo=UTC)
        expiration_date = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        vc_data = {
            **self.minimal_vc_data,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
        }
        vc = VerifiableCredentialModel(**vc_data)

        import json

        vc_json = vc.model_dump_json()
        vc_dict_serialized = json.loads(vc_json)

        self.assertEqual(vc_dict_serialized["issuanceDate"], "2023-01-01T12:00:00Z")
        self.assertEqual(vc_dict_serialized["expirationDate"], "2024-01-01T12:00:00Z")

    def test_vc_model_missing_required_fields(self):
        with self.assertRaises(ValidationError):
            VerifiableCredentialModel(
                id="urn:uuid:test-id"
            )  # Missing type, issuer, issuanceDate, credentialSubject

    def test_vc_model_assignment_validation(self):
        vc = VerifiableCredentialModel(**self.minimal_vc_data)
        with self.assertRaises(ValidationError):
            vc.issuer = 123  # type: ignore

        # Valid assignment
        new_issuer = "did:example:newissuer"
        vc.issuer = new_issuer
        self.assertEqual(vc.issuer, new_issuer)


if __name__ == "__main__":
    unittest.main()
