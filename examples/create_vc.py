# Create an unsigned vc
from pyakta.credentials import VerifiableCredential
from pyakta.did import DIDKey
from datetime import datetime, timedelta
import json

def create_vc():
    did_key_instance = DIDKey()
    did_key_instance.to_dict()

    vc_builder = VerifiableCredential()

    vc_builder.build(
        issuer_did=did_key_instance.did,
        subject_did=did_key_instance.did,
        credential_id=did_key_instance.did,
        types=["VerifiableCredential"],
        contexts=["https://www.w3.org/2018/credentials/v1"],
        issuance_date=datetime.now(),
        expiration_date=datetime.now() + timedelta(days=365),
        credential_subject={
            "id": did_key_instance.did,
            "name": "John Agent",
        }
    )
    print("---------------------------------------------------")
    print("Unsigned VC:\n")
    print(vc_builder.to_json(indent=4))

    # sign the vc
    vs_signed_vc = vc_builder.sign(
        issuer_signing_key=did_key_instance.signing_key,
        proof_purpose="assertionMethod",
        verification_method_id=did_key_instance.did,
    )
    print("---------------------------------------------------")
    print("Signed VC:\n")
    print(vs_signed_vc.to_json(indent=4))

if __name__ == "__main__":
    create_vc()