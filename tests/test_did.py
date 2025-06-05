import unittest
import base58
import re
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
from pyakta.exceptions import PyaktaError, DIDResolutionError

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
        with self.assertRaisesRegex(PyaktaError, "must start with 'z'"):
            _multibase_ed25519_to_public_bytes("abc")  # Does not start with z
        with self.assertRaisesRegex(
            PyaktaError, "Invalid Ed25519 multicodec prefix or key length"
        ):
            _multibase_ed25519_to_public_bytes(
                "z" + base58.b58encode(b"\x00" * 5).decode()
            )  # Too short
        with self.assertRaisesRegex(
            PyaktaError, "Invalid Ed25519 multicodec prefix or key length"
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
            PyaktaError, "Invalid did:key string format. Must start with 'did:key:z'."
        ):
            DIDKey(did_string="did:key:abc")
        # Test case for invalid base58 characters in the key part
        with self.assertRaisesRegex(PyaktaError, re.escape("Invalid character 'I'")):
            DIDKey(
                did_string="did:key:zInvalidBase58"
            )  # 'I' is not a valid base58 char
        # Test case for valid base58 but incorrect multicodec/length after decoding
        with self.assertRaisesRegex(
            PyaktaError, "Invalid Ed25519 multicodec prefix or key length"
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
        self.known_did_key_gen = DIDKey(
            private_key_multibase=KNOWN_PRIVATE_KEY_MULTIBASE_SEED
        )
        self.known_did_key_did_string = self.known_did_key_gen.did
        self.known_did_key_pk_multibase = self.known_did_key_gen.public_key_multibase
        self.known_did_key_verify_key = self.known_did_key_gen.verify_key

        # Create another distinct DIDKey for mismatch tests
        self.other_did_key_gen = DIDKey()
        self.other_did_key_pk_multibase = self.other_did_key_gen.public_key_multibase
        self.other_did_key_did_string = self.other_did_key_gen.did


    def test_resolve_did_key_direct_with_fragment(self):
        vm_url = f"{self.known_did_key_did_string}#{self.known_did_key_pk_multibase}"
        key = resolve_verification_key(vm_url)
        self.assertIsNotNone(key)
        self.assertEqual(key.encode(), self.known_did_key_verify_key.encode())

    def test_resolve_did_key_direct_no_fragment(self):
        vm_url = self.known_did_key_did_string
        key = resolve_verification_key(vm_url)
        self.assertIsNotNone(key)
        self.assertEqual(key.encode(), self.known_did_key_verify_key.encode())

    def test_resolve_did_key_error_fragment_mismatch(self):
        vm_url = f"{self.known_did_key_did_string}#{self.other_did_key_pk_multibase}"
        with self.assertRaisesRegex(DIDResolutionError, "Fragment .* does not match the resolved public key"):
            resolve_verification_key(vm_url)

    def test_resolve_did_key_error_invalid_did_key_format_in_url(self):
        vm_url = "did:key:invalidFormat" # Not starting with z, or otherwise malformed for DIDKey constructor
        with self.assertRaisesRegex(DIDResolutionError, "Error resolving did:key"):
            resolve_verification_key(vm_url)

    def test_resolve_issuer_hint_did_key_vm_url_matches_hint(self):
        vm_url = f"{self.known_did_key_did_string}#{self.known_did_key_pk_multibase}"
        key = resolve_verification_key(
            vm_url, issuer_did_hint=self.known_did_key_did_string
        )
        self.assertEqual(key.encode(), self.known_did_key_verify_key.encode())

    def test_resolve_issuer_hint_did_key_vm_url_is_hint_itself(self):
        vm_url = self.known_did_key_did_string # vm_url is the DID itself
        key = resolve_verification_key(
            vm_url, issuer_did_hint=self.known_did_key_did_string
        )
        self.assertEqual(key.encode(), self.known_did_key_verify_key.encode())
        
    def test_resolve_issuer_hint_did_key_error_vm_url_fragment_mismatch(self):
        # VM URL's DID part is known_did_key, but fragment points to other_did_key's pk.
        vm_url = f"{self.known_did_key_did_string}#{self.other_did_key_pk_multibase}"
        # This should be caught by the primary resolution path for vm_url itself.
        with self.assertRaisesRegex(DIDResolutionError, "Fragment .* does not match the resolved public key"):
            resolve_verification_key(vm_url, issuer_did_hint=self.known_did_key_did_string)

    def test_resolve_issuer_hint_did_key_error_vm_url_does_not_match_hint(self):
        # vm_url is not a did:key, so it falls to resolving via issuer_did_hint.
        # The vm_url (or its fragment) must then match the key derived from issuer_did_hint.
        vm_url_not_did_key = f"did:othermethod:12345#{self.other_did_key_pk_multibase}"
        with self.assertRaisesRegex(
            DIDResolutionError, 
            "Verification method .* publicKeyMultibase does not match that of the provided issuer DID"
        ):
            resolve_verification_key(vm_url_not_did_key, issuer_did_hint=self.known_did_key_did_string)

        vm_url_not_matching_did_key = f"{self.known_did_key_did_string}#incorrectFragment"
        with self.assertRaisesRegex(
            DIDResolutionError, 
            "Verification method .* publicKeyMultibase does not match that of the provided issuer DID"
        ):
             # This setup has vm_url which is a did:key (our known_did_key) but the fragment part "incorrectFragment"
             # does not match the actual public key multibase of known_did_key_did_string.
             # When resolve_verification_key tries to resolve issuer_did_hint (known_did_key_did_string),
             # it will get self.known_did_key_pk_multibase.
             # The vm_url fragment "incorrectFragment" must match this.
             # Note: This test case might be tricky due to how the logic branches.
             # If vm_url itself is a did:key, it will attempt direct resolution first.
             # Let's re-evaluate if this test is correctly set up for its intent.
             # The intent is: vm_url is *not* directly resolvable as a did:key (or is but points elsewhere),
             # so it relies on issuer_did_hint, and then the vm_url must match the key from the hint.
             #
             # If vm_url is `did:key:zABC#fragment1` and issuer_did_hint is `did:key:zABC` (which has key `zABCkey`),
             # then `fragment1` must be `zABCkey`.
             #
             # If vm_url is `did:other:123#fragment1` and issuer_did_hint is `did:key:zABC` (key `zABCkey`),
             # then `fragment1` must be `zABCkey`.
             # The current implementation checks `vm_fragment != did_key_resolver.public_key_multibase`

             # Let's simplify: vm_url is just a relative fragment, issuer_did_hint is the did:key
            resolve_verification_key(f"#{self.other_did_key_pk_multibase}", issuer_did_hint=self.known_did_key_did_string)


    def test_resolve_issuer_hint_did_key_vm_url_is_different_did_no_fragment_error(
        self,
    ):
        # vm_url is a did:key (other_did_key), different from issuer_did_hint (known_did_key).
        # Primary resolution of vm_url (other_did_key.did) should succeed and be used.
        # issuer_did_hint should ideally not affect this if vm_url is self-sufficient.
        key = resolve_verification_key(
            self.other_did_key_did_string, 
            issuer_did_hint=self.known_did_key_did_string
        )
        self.assertIsNotNone(key)
        self.assertEqual(key.encode(), self.other_did_key_gen.verify_key.encode())


    def test_resolve_error_no_vm_url_no_issuer_hint(self):
        with self.assertRaisesRegex(DIDResolutionError, "No verificationMethod in VC proof"):
            resolve_verification_key(None, None)
        with self.assertRaisesRegex(DIDResolutionError, "No verificationMethod in VC proof"):
            resolve_verification_key("", None)


    def test_resolve_vm_url_none_issuer_hint_is_did_key(self):
        # vm_url is None, issuer_did_hint is a resolvable did:key
        # resolve_verification_key should treat issuer_did_hint as the target vm_url
        key = resolve_verification_key(None, issuer_did_hint=self.known_did_key_did_string)
        self.assertIsNotNone(key)
        self.assertEqual(key.encode(), self.known_did_key_verify_key.encode())

    def test_resolve_vm_url_none_issuer_hint_not_did_key_returns_none(self):
        # If issuer_did_hint is not a did:key and no vm_url, it should return None
        key = resolve_verification_key(None, issuer_did_hint="did:web:example.com")
        self.assertIsNone(key)
        key = resolve_verification_key("", issuer_did_hint="did:web:example.com")
        self.assertIsNone(key)
        

    def test_resolve_error_unsupported_did_method_in_vm_url(self):
        vm_url = "did:unsupported:123"
        with self.assertRaisesRegex(DIDResolutionError, "Unsupported DID method or could not resolve key"):
            resolve_verification_key(vm_url)

    def test_resolve_error_unsupported_did_method_in_issuer_hint_only(self):
        # vm_url is None, and issuer_did_hint is an unsupported DID method.
        # This should return None as per current logic (it doesn't attempt to resolve non-did:key from hint alone)
        key = resolve_verification_key(None, issuer_did_hint="did:unsupported:123")
        self.assertIsNone(key)


    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_successful(self, mock_httpx_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:example.com",
                    "publicKeyMultibase": KNOWN_PUBLIC_KEY_MULTIBASE,
                }
            ],
        }
        mock_httpx_get.return_value = mock_response

        key = resolve_verification_key("did:web:example.com#key1")
        self.assertIsNotNone(key)
        self.assertEqual(key.encode(), KNOWN_PUBLIC_KEY_BYTES)
        mock_httpx_get.assert_called_once_with(
            "https://example.com/.well-known/did.json", timeout=10.0
        )

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_successful_with_path_and_port(self, mock_httpx_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:localhost:8080:user:alice",
            "verificationMethod": [
                {
                    "id": "did:web:localhost:8080:user:alice#key-xyz",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:localhost:8080:user:alice",
                    "publicKeyMultibase": KNOWN_PUBLIC_KEY_MULTIBASE,
                }
            ],
        }
        mock_httpx_get.return_value = mock_response

        key = resolve_verification_key(
            "did:web:localhost:8080:user:alice#key-xyz", did_web_scheme="http"
        )
        self.assertIsNotNone(key)
        self.assertEqual(key.encode(), KNOWN_PUBLIC_KEY_BYTES)
        mock_httpx_get.assert_called_once_with(
            "http://localhost:8080/user/alice/did.json", timeout=10.0
        )

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_http_status(self, mock_httpx_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=Mock(), response=mock_response
        )
        mock_httpx_get.return_value = mock_response

        with self.assertRaisesRegex(DIDResolutionError, "Error fetching DID Document"):
            resolve_verification_key("did:web:failing.com#key1")

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_http_request(self, mock_httpx_get):
        mock_httpx_get.side_effect = httpx.RequestError(
            "Connection failed", request=Mock()
        )
        with self.assertRaisesRegex(DIDResolutionError, "Error fetching DID Document"):
            resolve_verification_key("did:web:networkerror.com#key1")

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_json_decode(self, mock_httpx_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("err", "doc", 0)
        mock_httpx_get.return_value = mock_response

        with self.assertRaisesRegex(DIDResolutionError, "Error parsing DID Document"):
            resolve_verification_key("did:web:badjson.com#key1")

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_pydantic_validation(self, mock_httpx_get):
        mock_response = Mock()
        mock_response.status_code = 200
        # Missing 'id' which is required by DIDDocumentModel
        mock_response.json.return_value = {
            "@context": "https://www.w3.org/ns/did/v1",
            # "id": "did:web:pydanticfail.com", # ID is missing
            "verificationMethod": [],
        }
        mock_httpx_get.return_value = mock_response

        with self.assertRaisesRegex(DIDResolutionError, "Error parsing DID Document"):
            resolve_verification_key("did:web:pydanticfail.com#key1")

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_vm_not_found(self, mock_httpx_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:vmnotfound.com",
            "verificationMethod": [
                {
                    "id": "did:web:vmnotfound.com#someOtherKey",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:vmnotfound.com",
                    "publicKeyMultibase": KNOWN_PUBLIC_KEY_MULTIBASE,
                }
            ],
        }
        mock_httpx_get.return_value = mock_response

        with self.assertRaisesRegex(
            DIDResolutionError, "Verification method .* not found"
        ):
            resolve_verification_key("did:web:vmnotfound.com#key1")

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_vm_no_public_key_multibase(self, mock_httpx_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:nopkmb.com",
            "verificationMethod": [
                {
                    "id": "did:web:nopkmb.com#key1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:nopkmb.com",
                    # publicKeyMultibase is missing
                }
            ],
        }
        mock_httpx_get.return_value = mock_response

        with self.assertRaisesRegex(
            DIDResolutionError, "not found or has no publicKeyMultibase"
        ):
            resolve_verification_key("did:web:nopkmb.com#key1")

    @patch("pyakta.did.httpx.get")
    def test_resolve_did_web_error_vm_invalid_public_key_multibase(
        self, mock_httpx_get
    ):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:invalidpkmb.com",
            "verificationMethod": [
                {
                    "id": "did:web:invalidpkmb.com#key1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:invalidpkmb.com",
                    "publicKeyMultibase": "zInvalidKey",  # Not a valid multibase key
                }
            ],
        }
        mock_httpx_get.return_value = mock_response

        with self.assertRaisesRegex(
            DIDResolutionError, "Error parsing publicKeyMultibase from resolved VM"
        ):
            resolve_verification_key("did:web:invalidpkmb.com#key1")


if __name__ == "__main__":
    unittest.main()
