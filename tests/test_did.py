import unittest
import base58
from nacl.signing import SigningKey
from unittest.mock import patch, Mock
import httpx
import json

from pyakta.did import (
    DIDKey,
    DIDWeb,
    _public_bytes_to_multibase_ed25519,
    _multibase_ed25519_to_public_bytes,
    _private_seed_to_multibase,
    _multibase_to_private_seed,
    resolve_verification_key,
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


class TestDIDKeyResolveVerificationKey(unittest.TestCase):
    def setUp(self):
        # Use a known DIDKey for consistent testing
        # self.did_key_resolver_instance removed as resolve_verification_key is now a module function

        self.known_did_key_gen = DIDKey(
            private_key_multibase=KNOWN_PRIVATE_KEY_MULTIBASE_SEED
        )
        self.known_did_key_did_string = self.known_did_key_gen.did
        self.known_did_key_pk_multibase = self.known_did_key_gen.public_key_multibase
        self.known_did_key_verify_key = self.known_did_key_gen.verify_key

        # A different DIDKey for mismatch tests
        self.other_did_key_gen = DIDKey()  # Generate a new one
        self.other_did_key_did_string = self.other_did_key_gen.did
        self.other_did_key_pk_multibase = self.other_did_key_gen.public_key_multibase
        # self.other_did_key_verify_key = self.other_did_key_gen.verify_key # Not needed for current tests

    def test_resolve_did_key_direct_with_fragment(self):
        vm_url = f"{self.known_did_key_did_string}#{self.known_did_key_pk_multibase}"
        resolved_key = resolve_verification_key(vm_url)
        self.assertEqual(resolved_key, self.known_did_key_verify_key)

    def test_resolve_did_key_direct_no_fragment(self):
        vm_url = self.known_did_key_did_string
        resolved_key = resolve_verification_key(vm_url)
        self.assertEqual(resolved_key, self.known_did_key_verify_key)

    def test_resolve_did_key_error_fragment_mismatch(self):
        vm_url = f"{self.known_did_key_did_string}#{self.other_did_key_pk_multibase}"
        with self.assertRaisesRegex(
            ValueError, "Fragment .* does not match the resolved public key"
        ):
            resolve_verification_key(vm_url)

    def test_resolve_did_key_error_invalid_did_key_format_in_url(self):
        # This tests if DIDKey constructor within resolve_verification_key handles bad did:key input
        vm_url = "did:key:zInvalidKeyStructureForTest"
        with self.assertRaisesRegex(ValueError, "Error resolving did:key"):
            resolve_verification_key(vm_url)

    def test_resolve_issuer_hint_did_key_vm_url_matches_hint(self):
        vm_url = f"{self.known_did_key_did_string}#{self.known_did_key_pk_multibase}"
        resolved_key = resolve_verification_key(
            vm_url, issuer_did_hint=self.known_did_key_did_string
        )
        self.assertEqual(resolved_key, self.known_did_key_verify_key)

    def test_resolve_issuer_hint_did_key_vm_url_is_hint_itself(self):
        vm_url = self.known_did_key_did_string
        resolved_key = resolve_verification_key(
            vm_url, issuer_did_hint=self.known_did_key_did_string
        )
        self.assertEqual(resolved_key, self.known_did_key_verify_key)

    def test_resolve_issuer_hint_did_key_error_vm_url_fragment_mismatch(self):
        # VM URL fragment points to a different key than the one derived from the VM URL's DID part
        vm_url = f"{self.known_did_key_did_string}#{self.other_did_key_pk_multibase}"
        with self.assertRaisesRegex(
            ValueError, "Fragment .* does not match the resolved public key"
        ):
            resolve_verification_key(
                vm_url, issuer_did_hint=self.known_did_key_did_string
            )

    def test_resolve_issuer_hint_did_key_error_vm_url_does_not_match_hint(self):
        # VM URL is for a different DID Key than the hint, and hint resolution path is taken
        # This tests the fallback path where issuer_did_hint is a did:key, but vm_url is something else
        # and the vm_url must match the key from the issuer_did_hint.
        vm_url_that_is_not_did_key_or_web = (
            f"urn:example:different-controller#{self.other_did_key_pk_multibase}"
        )

        with self.assertRaisesRegex(
            ValueError,
            "Verification method .* publicKeyMultibase does not match that of the provided issuer DID",
        ):
            resolve_verification_key(
                verification_method_url=vm_url_that_is_not_did_key_or_web,  # This VM URL is for a different key and type
                issuer_did_hint=self.known_did_key_did_string,  # Hint is for our known_did_key
            )

    def test_resolve_issuer_hint_did_key_vm_url_is_different_did_no_fragment_error(
        self,
    ):
        # vm_url is a did:key, but different from issuer_did_hint (also did:key).
        # Primary resolution of vm_url (other_did_key_did_string) should succeed.
        # This setup will go through the first `if target_vm_url.startswith("did:key:")` block.
        resolved_key = resolve_verification_key(
            verification_method_url=self.other_did_key_did_string,
            issuer_did_hint=self.known_did_key_did_string,
        )
        # Should resolve to the key of other_did_key_did_string, not known_did_key_did_string
        self.assertEqual(resolved_key, self.other_did_key_gen.verify_key)
        self.assertNotEqual(resolved_key, self.known_did_key_verify_key)

    def test_resolve_error_no_vm_url_no_issuer_hint(self):
        with self.assertRaisesRegex(
            ValueError,
            "No verificationMethod in VC proof and no issuer_did hint provided",
        ):
            resolve_verification_key(verification_method_url=None, issuer_did_hint=None)

    def test_resolve_vm_url_none_issuer_hint_is_did_key(self):
        resolved_key = resolve_verification_key(
            verification_method_url=None, issuer_did_hint=self.known_did_key_did_string
        )
        self.assertEqual(resolved_key, self.known_did_key_verify_key)

    def test_resolve_vm_url_none_issuer_hint_not_did_key_returns_none(self):
        # If issuer_did_hint is not a did:key and no vm_url, it should return None (as per current logic)
        resolved_key = resolve_verification_key(
            verification_method_url=None, issuer_did_hint="did:foo:bar"
        )
        self.assertIsNone(resolved_key)

    def test_resolve_error_unsupported_did_method_in_vm_url(self):
        with self.assertRaisesRegex(
            ValueError, "Unsupported DID method or could not resolve key for"
        ):
            resolve_verification_key(verification_method_url="did:unsupported:123")

    def test_resolve_error_unsupported_did_method_in_issuer_hint_only(self):
        # If vm_url is None, and issuer_did_hint is an unsupported DID method for direct key derivation.
        # The current code returns None if issuer_did_hint is not did:key and vm_url is None.
        # If we want it to raise "Unsupported", the main function needs adjustment for that path.
        # For now, testing existing behavior which is to return None.
        resolved_key = resolve_verification_key(
            verification_method_url=None, issuer_did_hint="did:unsupported:123"
        )
        self.assertIsNone(resolved_key)

    # --- did:web tests ---
    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_successful(self, mock_httpx_get):
        domain = "example.com"
        vm_id_fragment = "key-1"
        vm_url = f"did:web:{domain}#{vm_id_fragment}"
        did_doc_url = f"https://{domain}/.well-known/did.json"

        mock_response = Mock()
        mock_response.json.return_value = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": f"did:web:{domain}",
            "verificationMethod": [
                {
                    "id": vm_url,
                    "type": "Ed25519VerificationKey2020",
                    "controller": f"did:web:{domain}",
                    "publicKeyMultibase": self.known_did_key_pk_multibase,
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_httpx_get.return_value = mock_response

        resolved_key = resolve_verification_key(vm_url)
        self.assertEqual(resolved_key, self.known_did_key_verify_key)
        mock_httpx_get.assert_called_once_with(did_doc_url, timeout=10.0)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_successful_with_path_and_port(self, mock_httpx_get):
        domain = "example.com"
        port = "8080"
        path_segments = ["users", "alice"]
        host_plus_port = f"{domain}:{port}"
        did_path = ":".join(path_segments)
        vm_id_fragment = "keyByAlice"

        did_web_string = f"did:web:{host_plus_port}:{did_path}"
        vm_url = f"{did_web_string}#{vm_id_fragment}"
        did_doc_url = f"https://{host_plus_port}/{'/'.join(path_segments)}/did.json"

        mock_response = Mock()
        mock_response.json.return_value = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did_web_string,
            "verificationMethod": [
                {
                    "id": vm_url,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did_web_string,
                    "publicKeyMultibase": self.known_did_key_pk_multibase,
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_httpx_get.return_value = mock_response

        resolved_key = resolve_verification_key(vm_url, did_web_scheme="https")
        self.assertEqual(resolved_key, self.known_did_key_verify_key)
        mock_httpx_get.assert_called_once_with(did_doc_url, timeout=10.0)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_http_status(self, mock_httpx_get):
        vm_url = "did:web:failing.com#key-1"
        mock_httpx_get.side_effect = httpx.HTTPStatusError(
            "Error", request=Mock(), response=Mock(status_code=404)
        )
        with self.assertRaisesRegex(
            ValueError,
            "Error fetching DID Document from https://failing.com/.well-known/did.json: HTTP 404",
        ):
            resolve_verification_key(vm_url)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_http_request(self, mock_httpx_get):
        vm_url = "did:web:timeout.com#key-1"
        mock_httpx_get.side_effect = httpx.RequestError("Timeout", request=Mock())
        with self.assertRaisesRegex(
            ValueError,
            "Error fetching DID Document from https://timeout.com/.well-known/did.json: Timeout",
        ):
            resolve_verification_key(vm_url)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_json_decode(self, mock_httpx_get):
        vm_url = "did:web:badjson.com#key-1"
        mock_response = Mock()
        mock_response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
        mock_response.raise_for_status = Mock()
        mock_httpx_get.return_value = mock_response
        with self.assertRaisesRegex(
            ValueError,
            "Error parsing DID Document from https://badjson.com/.well-known/did.json:",
        ):
            resolve_verification_key(vm_url)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_pydantic_validation(self, mock_httpx_get):
        vm_url = "did:web:invalidmodel.com#key-1"
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": "did:web:invalidmodel.com",
            "invalidField": True,
        }  # Missing verificationMethod
        mock_response.raise_for_status = Mock()
        mock_httpx_get.return_value = mock_response
        with self.assertRaisesRegex(
            ValueError,
            "Error parsing DID Document from https://invalidmodel.com/.well-known/did.json:",
        ):
            resolve_verification_key(vm_url)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_vm_not_found(self, mock_httpx_get):
        domain = "example.com"
        vm_url = f"did:web:{domain}#nonexistent-key"
        mock_response = Mock()
        mock_response.json.return_value = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": f"did:web:{domain}",
            "verificationMethod": [
                {
                    "id": f"did:web:{domain}#actual-key",
                    "type": "Ed25519VerificationKey2020",
                    "controller": f"did:web:{domain}",
                    "publicKeyMultibase": self.known_did_key_pk_multibase,
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_httpx_get.return_value = mock_response
        with self.assertRaisesRegex(
            ValueError, "Verification method .* not found or has no publicKeyMultibase"
        ):
            resolve_verification_key(vm_url)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_vm_no_public_key_multibase(self, mock_httpx_get):
        domain = "example.com"
        vm_id_fragment = "key-no-pkmb"
        vm_url = f"did:web:{domain}#{vm_id_fragment}"
        mock_response = Mock()
        mock_response.json.return_value = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": f"did:web:{domain}",
            "verificationMethod": [
                {
                    "id": vm_url,
                    "type": "Ed25519VerificationKey2020",
                    "controller": f"did:web:{domain}",
                }
                # Missing publicKeyMultibase
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_httpx_get.return_value = mock_response
        with self.assertRaisesRegex(
            ValueError, "Verification method .* not found or has no publicKeyMultibase"
        ):
            resolve_verification_key(vm_url)

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_vm_invalid_public_key_multibase(
        self, mock_httpx_get
    ):
        domain = "example.com"
        vm_id_fragment = "key-invalid-pkmb"
        vm_url = f"did:web:{domain}#{vm_id_fragment}"
        mock_response = Mock()
        mock_response.json.return_value = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": f"did:web:{domain}",
            "verificationMethod": [
                {
                    "id": vm_url,
                    "type": "Ed25519VerificationKey2020",
                    "controller": f"did:web:{domain}",
                    "publicKeyMultibase": "zInvalidBase58",
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_httpx_get.return_value = mock_response
        with self.assertRaisesRegex(
            ValueError, "Error parsing publicKeyMultibase from resolved VM"
        ):
            resolve_verification_key(vm_url)


if __name__ == "__main__":
    unittest.main()
