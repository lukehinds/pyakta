from typing import Any, Dict, List, Optional

import base58
from nacl.signing import SigningKey, VerifyKey

from .models import DIDDocumentModel, DIDKeyModel, DIDWebModel, VerificationMethodModel


def _public_bytes_to_multibase_ed25519(key_bytes: bytes) -> str:
    # Ed25519 public key multicodec prefix (0xed01)
    # 0xed -> Ed25519 public key
    # 0x01 -> varint encoding of the length of the key (32 bytes).
    # Actually, for Ed25519, 0xed is the code, and the 0x01 appears to be part of the varint representation of the code itself,
    # or a historically used prefix component. The raw key directly follows.
    # Standard multicodec for ed25519-pub is 0xed.
    # However, did:key often uses a 2-byte prefix 0xed01 before the 32-byte key.
    # Let's stick to what's common for did:key context.
    codec_prefix = bytes(
        [0xED, 0x01]
    )  # Prefix for Ed25519 public key in did:key context
    multicodec_pubkey = codec_prefix + key_bytes
    return "z" + base58.b58encode(multicodec_pubkey).decode("utf-8")


def _multibase_ed25519_to_public_bytes(multibase_key: str) -> bytes:
    if not multibase_key.startswith("z"):
        raise ValueError("Ed25519 Multibase key must start with 'z'")
    multicodec_pubkey = base58.b58decode(multibase_key[1:])
    # Expecting 0xed01 prefix then 32 bytes of key
    if (
        multicodec_pubkey.startswith(bytes([0xED, 0x01]))
        and len(multicodec_pubkey) == 34
    ):
        return multicodec_pubkey[2:]
    # Support for just 0xed prefix (less common in did:key but possible)
    elif multicodec_pubkey.startswith(bytes([0xED])) and len(multicodec_pubkey) == 33:
        return multicodec_pubkey[1:]
    else:
        raise ValueError("Invalid Ed25519 multicodec prefix or key length.")


def _private_seed_to_multibase(seed_bytes: bytes) -> str:
    # Simply base58btc encode the 32-byte seed.
    # No 'z' prefix for private keys, it's just the encoded seed.
    return base58.b58encode(seed_bytes).decode("utf-8")


def _multibase_to_private_seed(multibase_seed: str) -> bytes:
    return base58.b58decode(multibase_seed)


class DIDKey:
    """Represents a Decentralized Identifier using the did:key method."""

    def __init__(
        self,
        private_key_multibase: Optional[str] = None,
        did_string: Optional[str] = None,
    ):
        """
        Initializes a DIDKey instance.

        The initialization follows these rules:
        1. If `did_string` is provided (e.g., "did:key:z..."), the public key is derived from it.
           No private key will be available. Only Ed25519 keys are supported.
        2. If `private_key_multibase` (base58btc encoded 32-byte seed) is provided (and `did_string` is not),
           the key pair is derived from this private key.
        3. If neither is provided, a new Ed25519 key pair is generated.

        Args:
            private_key_multibase: Optional base58btc encoded private key seed.
            did_string: Optional did:key string (e.g., "did:key:z...").
        """
        self._signing_key: Optional[SigningKey] = None
        self._verify_key: Optional[VerifyKey] = None
        self._public_key_bytes: Optional[bytes] = None
        self._did: Optional[str] = None
        self._private_key_multibase: Optional[str] = None
        self._public_key_multibase: Optional[str] = (
            None  # The 'z...' string for public key
        )

        if did_string:
            if not did_string.startswith("did:key:z"):
                raise ValueError(
                    "Invalid did:key string format. Must start with 'did:key:z'."
                )

            self._public_key_multibase = did_string[
                len("did:key:") :
            ]  # Store the 'z...' part
            self._public_key_bytes = _multibase_ed25519_to_public_bytes(
                self._public_key_multibase
            )
            self._verify_key = VerifyKey(self._public_key_bytes)
            self._did = did_string

        elif private_key_multibase:
            seed_bytes = _multibase_to_private_seed(private_key_multibase)
            self._signing_key = SigningKey(seed_bytes)
            self._verify_key = self._signing_key.verify_key
            self._public_key_bytes = self._verify_key.encode()
            self._public_key_multibase = _public_bytes_to_multibase_ed25519(
                self._public_key_bytes
            )
            self._private_key_multibase = private_key_multibase
            self._did = f"did:key:{self._public_key_multibase}"
        else:
            self._signing_key = SigningKey.generate()
            self._verify_key = self._signing_key.verify_key
            self._public_key_bytes = self._verify_key.encode()
            self._private_key_multibase = _private_seed_to_multibase(
                self._signing_key.encode()
            )
            self._public_key_multibase = _public_bytes_to_multibase_ed25519(
                self._public_key_bytes
            )
            self._did = f"did:key:{self._public_key_multibase}"

    @property
    def did(self) -> Optional[str]:
        return self._did

    @property
    def verify_key(self) -> Optional[VerifyKey]:
        return self._verify_key

    @property
    def signing_key(self) -> Optional[SigningKey]:
        return self._signing_key

    @property
    def public_key_multibase(self) -> Optional[str]:
        return self._public_key_multibase

    @property
    def public_key_bytes(self) -> Optional[bytes]:
        return self._public_key_bytes

    @property
    def private_key_multibase(self) -> Optional[str]:
        return self._private_key_multibase

    def to_dict(self) -> Dict[str, str]:
        """Returns a dictionary representation of the DID key (multibase format)."""
        if not self._did or not self._public_key_multibase:
            raise ValueError("DIDKey object is not fully initialized for to_dict.")
        data = {"did": self._did, "publicKeyMultibase": self._public_key_multibase}
        if self._private_key_multibase:
            data["privateKeyMultibase"] = self._private_key_multibase

        data["verification_method_example"] = f"{self._did}#controller"
        data["verification_method_example_did_key"] = (
            f"{self._did}#{self._public_key_multibase}"
        )

        return data

    def to_model(self) -> DIDKeyModel:
        """Returns a Pydantic model representation of the DID key."""
        if not self._did or not self._public_key_multibase:
            raise ValueError("DIDKey object is not fully initialized for to_model.")
        return DIDKeyModel(
            did=self._did,
            publicKeyMultibase=self._public_key_multibase,  # This is the 'z...' string
            privateKeyMultibase=self._private_key_multibase,
        )


class DIDWeb:
    """Represents a Decentralized Identifier using the did:web method."""

    def __init__(
        self,
        domain: str,
        path: Optional[List[str]] = None,
        private_key_multibase: Optional[str] = None,
    ):
        """
        Initializes a DIDWeb instance.

        A new Ed25519 key pair is generated unless `private_key_multibase` (base58btc encoded seed) is provided.
        The DID Document is constructed based on the domain and optional path.

        Args:
            domain: The domain name for the did:web (e.g., "example.com").
            path: Optional list of path segments for the did:web (e.g., [\"users\", \"alice\"]).
            private_key_multibase: Optional base58btc encoded private key seed.
        """
        if private_key_multibase:
            seed_bytes = _multibase_to_private_seed(private_key_multibase)
            self._signing_key = SigningKey(seed_bytes)
        else:
            self._signing_key = SigningKey.generate()

        self._verify_key = self._signing_key.verify_key
        self._public_key_bytes = self._verify_key.encode()

        self._private_key_multibase = _private_seed_to_multibase(
            self._signing_key.encode()
        )
        self._public_key_multibase = _public_bytes_to_multibase_ed25519(
            self._public_key_bytes
        )  # 'z...'

        did_web_string = f"did:web:{domain.lower()}"
        if path:
            processed_path_segments = [
                segment.strip("/") for segment in path if segment.strip("/")
            ]
            if processed_path_segments:
                processed_path = ":".join(processed_path_segments)
                did_web_string += f":{processed_path}"
        self._did = did_web_string

        # For did:web, the key ID often includes the full DID plus a fragment.
        # Using #key-1 is a common convention, but could also be #controller or even the public key multibase.
        # For simplicity and consistency with what Ed25519VerificationKey2020 might expect as a fragment,
        # lets use a generic key-1, but a more specific one like #<publicKeyMultibase> could be used.
        self._key_id_fragment = "key-1"
        self._key_id = f"{self._did}#{self._key_id_fragment}"

        verification_method = VerificationMethodModel(
            id=self._key_id,
            type="Ed25519VerificationKey2020",
            controller=self._did,
            publicKeyMultibase=self._public_key_multibase,
        )

        self._did_document_model = DIDDocumentModel(
            context=[
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            id=self._did,
            verificationMethod=[verification_method],
            authentication=[self._key_id],
            assertionMethod=[self._key_id],
        )

    @property
    def did(self) -> str:
        return self._did

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def verify_key(self) -> VerifyKey:
        return self._verify_key

    @property
    def signing_key(self) -> SigningKey:
        return self._signing_key

    @property
    def public_key_multibase(self) -> str:
        return self._public_key_multibase

    @property
    def private_key_multibase(self) -> str:
        return self._private_key_multibase

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def did_document(self) -> Dict[str, Any]:
        """Returns the DID Document as a dictionary, using Pydantic model dump."""
        return self._did_document_model.model_dump(by_alias=True, exclude_none=True)

    def to_dict(self) -> Dict[str, Any]:
        """Returns key information dictionary (multibase format)."""
        return {
            "did": self._did,
            "publicKeyMultibase": self._public_key_multibase,
            "privateKeyMultibase": self._private_key_multibase,
            "key_id": self._key_id,
            "verification_method_example": self._key_id,
        }

    def to_model(self) -> DIDWebModel:
        """Returns a Pydantic model representation of the DIDWeb instance."""
        return DIDWebModel(
            did=self._did,
            did_document=self._did_document_model,
            privateKeyMultibase=self._private_key_multibase,
            publicKeyMultibase=self._public_key_multibase,
            key_id=self._key_id,
        )
