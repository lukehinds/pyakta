import unittest
import base58
from nacl.signing import SigningKey

from pyakta.did import (
    DIDKey,
    DIDWeb,
    _public_bytes_to_multibase_ed25519,
    _multibase_ed25519_to_public_bytes,
    _private_seed_to_multibase,
    _multibase_to_private_seed,
)
from pyakta.models import DIDDocumentModel, DIDKeyModel, DIDWebModel

# Known Ed25519 key pair (seed, public key bytes, multibase public key, multibase private seed)
KNOWN_SEED_BYTES = b"\x00" * 31 + b"\x01"  # 32 bytes seed
KNOWN_SIGNING_KEY = SigningKey(KNOWN_SEED_BYTES)
KNOWN_VERIFY_KEY = KNOWN_SIGNING_KEY.verify_key
KNOWN_PUBLIC_KEY_BYTES = KNOWN_VERIFY_KEY.encode()
# Expected multibase for 0xed01 + 32 bytes public key
KNOWN_PUBLIC_KEY_MULTIBASE = _public_bytes_to_multibase_ed25519(KNOWN_PUBLIC_KEY_BYTES)
KNOWN_PRIVATE_KEY_MULTIBASE_SEED = _private_seed_to_multibase(KNOWN_SEED_BYTES)


class TestDIDKeyHelperFunctions(unittest.TestCase):
    def test_public_key_multibase_conversion_roundtrip(self):
        # Use a newly generated key for this roundtrip
        sk = SigningKey.generate()
        vk = sk.verify_key
        public_bytes = vk.encode()

        multibase_z = _public_bytes_to_multibase_ed25519(public_bytes)
        self.assertTrue(multibase_z.startswith("z"))

        decoded_bytes = _multibase_ed25519_to_public_bytes(multibase_z)
        self.assertEqual(public_bytes, decoded_bytes)

    def test_public_key_multibase_conversion_known(self):
        # Test with our known public key
        multibase_z = _public_bytes_to_multibase_ed25519(KNOWN_PUBLIC_KEY_BYTES)
        self.assertEqual(multibase_z, KNOWN_PUBLIC_KEY_MULTIBASE)

        decoded_bytes = _multibase_ed25519_to_public_bytes(KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertEqual(KNOWN_PUBLIC_KEY_BYTES, decoded_bytes)

    def test_multibase_to_public_bytes_invalid(self):
        with self.assertRaisesRegex(ValueError, "must start with 'z'"):
            _multibase_ed25519_to_public_bytes("abc")  # Does not start with z
        with self.assertRaisesRegex(
            ValueError, "Invalid Ed25519 multicodec prefix or key length"
        ):
            _multibase_ed25519_to_public_bytes(
                "z" + base58.b58encode(b"\x00" * 5).decode()
            )  # Too short
        with self.assertRaisesRegex(
            ValueError, "Invalid Ed25519 multicodec prefix or key length"
        ):
            _multibase_ed25519_to_public_bytes(
                "z" + base58.b58encode(b"\xff\xff" + b"\x00" * 32).decode()
            )  # Wrong prefix

    def test_private_key_multibase_conversion_roundtrip(self):
        # Use a newly generated key for this roundtrip
        sk = SigningKey.generate()
        seed_bytes = sk.encode()  # This is the seed

        multibase_seed_str = _private_seed_to_multibase(seed_bytes)
        # Should not start with z typically for private seeds in this format
        self.assertFalse(multibase_seed_str.startswith("z"))

        decoded_seed_bytes = _multibase_to_private_seed(multibase_seed_str)
        self.assertEqual(seed_bytes, decoded_seed_bytes)

    def test_private_key_multibase_conversion_known(self):
        multibase_seed_str = _private_seed_to_multibase(KNOWN_SEED_BYTES)
        self.assertEqual(multibase_seed_str, KNOWN_PRIVATE_KEY_MULTIBASE_SEED)

        decoded_seed = _multibase_to_private_seed(KNOWN_PRIVATE_KEY_MULTIBASE_SEED)
        self.assertEqual(decoded_seed, KNOWN_SEED_BYTES)


class TestDIDKey(unittest.TestCase):
    def test_did_key_generation_new(self):
        did_key = DIDKey()
        self.assertIsNotNone(did_key.did)
        self.assertTrue(did_key.did.startswith("did:key:z"))
        self.assertIsNotNone(did_key.signing_key)
        self.assertIsNotNone(did_key.verify_key)
        self.assertIsNotNone(did_key.public_key_multibase)
        self.assertTrue(did_key.public_key_multibase.startswith("z"))
        self.assertIsNotNone(did_key.private_key_multibase)
        self.assertEqual(len(did_key.public_key_bytes), 32)

    def test_did_key_from_private_multibase(self):
        did_key = DIDKey(private_key_multibase=KNOWN_PRIVATE_KEY_MULTIBASE_SEED)
        self.assertEqual(did_key.did, f"did:key:{KNOWN_PUBLIC_KEY_MULTIBASE}")
        self.assertEqual(did_key.public_key_multibase, KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertEqual(
            did_key.private_key_multibase, KNOWN_PRIVATE_KEY_MULTIBASE_SEED
        )
        self.assertIsNotNone(did_key.signing_key)
        self.assertIsNotNone(did_key.verify_key)
        self.assertEqual(did_key.public_key_bytes, KNOWN_PUBLIC_KEY_BYTES)

    def test_did_key_from_did_string(self):
        did_string = f"did:key:{KNOWN_PUBLIC_KEY_MULTIBASE}"
        did_key = DIDKey(did_string=did_string)
        self.assertEqual(did_key.did, did_string)
        self.assertEqual(did_key.public_key_multibase, KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertIsNone(did_key.signing_key)
        self.assertIsNone(did_key.private_key_multibase)
        self.assertIsNotNone(did_key.verify_key)
        self.assertEqual(did_key.public_key_bytes, KNOWN_PUBLIC_KEY_BYTES)

    def test_did_key_invalid_did_string(self):
        with self.assertRaisesRegex(
            ValueError, "Invalid did:key string format. Must start with 'did:key:z'."
        ):
            DIDKey(did_string="did:key:abc")
        # Test case for invalid base58 characters in the key part
        with self.assertRaisesRegex(ValueError, "Invalid character"):
            DIDKey(
                did_string="did:key:zInvalidBase58"
            )  # 'I' is not a valid base58 char
        # Test case for valid base58 but incorrect multicodec/length after decoding
        with self.assertRaisesRegex(
            ValueError, "Invalid Ed25519 multicodec prefix or key length"
        ):
            DIDKey(
                did_string="did:key:z" + base58.b58encode(b"short").decode()
            )  # Valid base58, but content is wrong

    def test_did_key_to_dict_with_private_key(self):
        did_key = DIDKey(private_key_multibase=KNOWN_PRIVATE_KEY_MULTIBASE_SEED)
        key_dict = did_key.to_dict()
        expected_did = f"did:key:{KNOWN_PUBLIC_KEY_MULTIBASE}"
        self.assertEqual(key_dict["did"], expected_did)
        self.assertEqual(key_dict["publicKeyMultibase"], KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertEqual(
            key_dict["privateKeyMultibase"], KNOWN_PRIVATE_KEY_MULTIBASE_SEED
        )
        self.assertEqual(
            key_dict["verification_method_example"], f"{expected_did}#controller"
        )
        self.assertEqual(
            key_dict["verification_method_example_did_key"],
            f"{expected_did}#{KNOWN_PUBLIC_KEY_MULTIBASE}",
        )

    def test_did_key_to_dict_public_only(self):
        did_string = f"did:key:{KNOWN_PUBLIC_KEY_MULTIBASE}"
        did_key = DIDKey(did_string=did_string)
        key_dict = did_key.to_dict()
        self.assertEqual(key_dict["did"], did_string)
        self.assertEqual(key_dict["publicKeyMultibase"], KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertNotIn("privateKeyMultibase", key_dict)

    def test_did_key_to_model(self):
        did_key = DIDKey(private_key_multibase=KNOWN_PRIVATE_KEY_MULTIBASE_SEED)
        key_model = did_key.to_model()
        self.assertIsInstance(key_model, DIDKeyModel)
        self.assertEqual(key_model.did, f"did:key:{KNOWN_PUBLIC_KEY_MULTIBASE}")
        self.assertEqual(key_model.publicKeyMultibase, KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertEqual(
            key_model.privateKeyMultibase, KNOWN_PRIVATE_KEY_MULTIBASE_SEED
        )

    def test_did_key_to_model_public_only(self):
        did_key_obj = DIDKey(did_string=f"did:key:{KNOWN_PUBLIC_KEY_MULTIBASE}")
        key_model = did_key_obj.to_model()
        self.assertIsInstance(key_model, DIDKeyModel)
        self.assertEqual(key_model.did, f"did:key:{KNOWN_PUBLIC_KEY_MULTIBASE}")
        self.assertEqual(key_model.publicKeyMultibase, KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertIsNone(key_model.privateKeyMultibase)


class TestDIDWeb(unittest.TestCase):
    def test_did_web_generation_simple_domain(self):
        domain = "example.com"
        did_web = DIDWeb(domain=domain)
        expected_did = f"did:web:{domain}"
        self.assertEqual(did_web.did, expected_did)
        self.assertTrue(did_web.public_key_multibase.startswith("z"))
        self.assertIsNotNone(did_web.private_key_multibase)
        self.assertIsNotNone(did_web.signing_key)
        self.assertIsNotNone(did_web.verify_key)
        self.assertEqual(did_web.key_id, f"{expected_did}#key-1")

        doc = did_web.did_document
        self.assertEqual(
            doc["@context"],
            [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
        )
        self.assertEqual(doc["id"], expected_did)
        self.assertEqual(len(doc["verificationMethod"]), 1)
        vm = doc["verificationMethod"][0]
        self.assertEqual(vm["id"], did_web.key_id)
        self.assertEqual(vm["type"], "Ed25519VerificationKey2020")
        self.assertEqual(vm["controller"], expected_did)
        self.assertEqual(vm["publicKeyMultibase"], did_web.public_key_multibase)
        self.assertEqual(doc["authentication"], [did_web.key_id])
        self.assertEqual(doc["assertionMethod"], [did_web.key_id])

    def test_did_web_generation_with_path(self):
        domain = "example.com"
        path = ["users", "alice"]
        did_web = DIDWeb(domain=domain, path=path)
        expected_did = f"did:web:{domain}:users:alice"
        self.assertEqual(did_web.did, expected_did)
        self.assertEqual(did_web.key_id, f"{expected_did}#key-1")
        doc = did_web.did_document
        self.assertEqual(doc["id"], expected_did)
        self.assertEqual(doc["verificationMethod"][0]["id"], did_web.key_id)
        self.assertEqual(doc["verificationMethod"][0]["controller"], expected_did)

    def test_did_web_generation_with_path_slashes_and_empty(self):
        domain = "example.com"
        path = ["/folder1/", "", "item2"]
        did_web = DIDWeb(domain=domain, path=path)
        expected_did = f"did:web:{domain}:folder1:item2"
        self.assertEqual(did_web.did, expected_did)
        self.assertEqual(did_web.key_id, f"{expected_did}#key-1")

    def test_did_web_from_private_multibase(self):
        domain = "test.domain.org"
        did_web = DIDWeb(
            domain=domain, private_key_multibase=KNOWN_PRIVATE_KEY_MULTIBASE_SEED
        )
        self.assertEqual(
            did_web.private_key_multibase, KNOWN_PRIVATE_KEY_MULTIBASE_SEED
        )
        self.assertEqual(did_web.public_key_multibase, KNOWN_PUBLIC_KEY_MULTIBASE)
        self.assertEqual(did_web.did, f"did:web:{domain}")

    def test_did_web_to_dict(self):
        did_web = DIDWeb(domain="example.to.dict")
        web_dict = did_web.to_dict()
        self.assertEqual(web_dict["did"], did_web.did)
        self.assertEqual(web_dict["publicKeyMultibase"], did_web.public_key_multibase)
        self.assertEqual(web_dict["privateKeyMultibase"], did_web.private_key_multibase)
        self.assertEqual(web_dict["key_id"], did_web.key_id)
        self.assertEqual(web_dict["verification_method_example"], did_web.key_id)

    def test_did_web_to_model(self):
        did_web = DIDWeb(domain="example.to.model")
        web_model = did_web.to_model()
        self.assertIsInstance(web_model, DIDWebModel)
        self.assertEqual(web_model.did, did_web.did)
        self.assertEqual(web_model.publicKeyMultibase, did_web.public_key_multibase)
        self.assertEqual(web_model.privateKeyMultibase, did_web.private_key_multibase)
        self.assertEqual(web_model.key_id, did_web.key_id)
        self.assertIsInstance(web_model.did_document, DIDDocumentModel)
        self.assertEqual(web_model.did_document.id, did_web.did)
        self.assertEqual(
            web_model.did_document.verificationMethod[0].id, did_web.key_id
        )


if __name__ == "__main__":
    unittest.main()
