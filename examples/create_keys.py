from pyakta.did import DIDKey, DIDWeb

def _prepare_issuer_key_file_data(did_data: dict, verification_method: str) -> dict:
    """Prepares the dictionary for an issuer key file from DID data."""
    return {
        "did": did_data.get("did"),
        "publicKeyMultibase": did_data.get("publicKeyMultibase"),
        "privateKeyMultibase": did_data.get("privateKeyMultibase"),
        "verificationMethod": verification_method
    }

def create_keys():
    did_key_instance = DIDKey()
    print(_prepare_issuer_key_file_data(did_key_instance.to_dict(), "verificationMethod"))

    did_web_instance = DIDWeb(domain="agent.example.com", path=["users", "1234567890"])
    print(_prepare_issuer_key_file_data(did_web_instance.to_dict(), "verificationMethod"))

if __name__ == "__main__":
    create_keys()