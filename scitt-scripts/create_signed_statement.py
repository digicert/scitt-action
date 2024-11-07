""" Module for creating a SCITT signed statement """

import argparse
import hashlib
import json

from typing import Optional
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey
from pycose.algorithms import Es256
from pycose.headers import Algorithm, KID, ContentType, X5t, X5chain
from pycose.keys.curves import P256
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys.keyparam import KpKty, EC2KpD, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

import digicert_stm_client
import identity
import key

# subject header label comes from version 2 of the scitt architecture document
# https://www.ietf.org/archive/id/draft-birkholz-scitt-architecture-02.html#name-envelope-and-claim-format
HEADER_LABEL_FEED = 392

# CWT header label comes from version 4 of the scitt architecture document
# https://www.ietf.org/archive/id/draft-ietf-scitt-architecture-04.html#name-issuer-identity
HEADER_LABEL_CWT = 15

# Various CWT header labels come from:
# https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1
HEADER_LABEL_CWT_ISSUER = 1
HEADER_LABEL_CWT_SUBJECT = 2

# CWT CNF header labels come from:
# https://datatracker.ietf.org/doc/html/rfc8747#name-confirmation-claim
HEADER_LABEL_CWT_CNF = 8
HEADER_LABEL_CNF_COSE_KEY = 1

# Signed Hash envelope header labels from:
# https://github.com/OR13/draft-steele-cose-hash-envelope/blob/main/draft-steele-cose-hash-envelope.md
# pre-adoption/private use parameters
# https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
HEADER_LABEL_PAYLOAD_HASH_ALGORITHM = -6800
HEADER_LABEL_LOCATION = -6801

# CBOR Object Signing and Encryption (COSE) "typ" (type) Header Parameter
# https://datatracker.ietf.org/doc/rfc9596/
HEADER_LABEL_TYPE = 16
COSE_TYPE="application/hashed+cose"

def open_signing_key(key_file: str) -> SigningKey:
    """
    opens the signing key from the key file.
    NOTE: the signing key is expected to be a P-256 ecdsa key in PEM format.
    While this sample script uses P-256 ecdsa, DataTrails supports any format
    supported through [go-cose](https://github.com/veraison/go-cose/blob/main/algorithm.go)
    """
    with open(key_file, encoding="UTF-8") as file:
        signing_key = SigningKey.from_pem(file.read(), hashlib.sha256)
        return signing_key


def open_payload(payload_file: str) -> str:
    """
    opens the payload from the payload file.
    """
    with open(payload_file, encoding="UTF-8") as file:
        return file.read()


def create_signed_statement(
    issuer: identity.Identity,
    payload: str,
    subject: str,
    private_key: key.IssuerPrivateKey,
    content_type: str,
    payload_location: str,
) -> bytes:
    """
    creates a signed statement, given the private key, payload, subject and issuer
    the payload will be hashed and the hash added to the payload field.
    """

    ec_public_numbers = issuer.public_key.public_numbers()

    x_part = ec_public_numbers.x.to_bytes(32, byteorder='big')
    y_part = ec_public_numbers.y.to_bytes(32, byteorder='big')

    # create a protected header where
    #  the verification key is attached to the cwt claims
    protected_header = {
        HEADER_LABEL_TYPE: COSE_TYPE,
        Algorithm: Es256,
        KID: issuer.kid.encode(),
        ContentType: content_type,
        X5t: issuer.x5t,
        HEADER_LABEL_CWT: {
            HEADER_LABEL_CWT_ISSUER: issuer.iss,
            HEADER_LABEL_CWT_SUBJECT: subject,
            HEADER_LABEL_CWT_CNF: {
                HEADER_LABEL_CNF_COSE_KEY: {
                    KpKty: KtyEC2,
                    EC2KpCurve: P256,
                    EC2KpX: x_part,
                    EC2KpY: y_part,
                },
            },
        },
        HEADER_LABEL_PAYLOAD_HASH_ALGORITHM: -16,  # for sha256
        HEADER_LABEL_LOCATION: payload_location,
    }

    unprotected_header = {
        X5chain: issuer.x5chain
    }

    # now create a sha256 hash of the payload
    #
    # NOTE: any hashing algorithm can be used.
    payload_hash = sha256(payload.encode("utf-8")).digest()

    # create the statement as a sign1 message using the protected header,
    # unprotected header, and payload
    statement = Sign1Message(
        phdr=protected_header,
        uhdr=unprotected_header,
        payload=payload_hash
    )

    # HACK: get TBS
    tbs = statement._sig_structure

    # HACK: this is gross
    statement._signature = private_key.sign(tbs)

    # encode the statement again to include the signature foisted into the object
    encoded = statement.encode(sign=False)

    return encoded


def main():
    """Creates a signed statement"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # content-type
    parser.add_argument(
        "--content-type",
        type=str,
        help="The iana.org media type for the payload",
        default="application/json",
    )

    # payload-file (a reference to the file that will become the payload of the SCITT Statement)
    parser.add_argument(
        "--payload-file",
        type=str,
        help="filepath to the content that will become the payload of the SCITT Statement "
        "(currently limited to json format).",
        default="scitt-payload.json",
    )

    # payload-location
    parser.add_argument(
        "--payload-location",
        type=str,
        help="location hint for the original statement that was hashed.",
    )

    # subject
    parser.add_argument(
        "--subject",
        type=str,
        required=True,
        help="subject to correlate statements made about an artifact.",
    )

    # output file
    parser.add_argument(
        "--output-file",
        type=str,
        help="name of the output file to store the signed statement.",
        default="signed-statement.cbor",
    )

    args = parser.parse_args()

    payload = open_payload(args.payload_file)

    stm_client = digicert_stm_client.DigiCertSoftwareTrustManagerClient()

    signed_statement = create_signed_statement(
        content_type=args.content_type,
        issuer=stm_client.retrieve_identity(),
        payload=payload,
        payload_location=args.payload_location,
        private_key=digicert_stm_client.DigiCertStmPrivateKey(),
        subject=args.subject
    )


    with open(args.output_file, "wb") as output_file:
        output_file.write(signed_statement)


if __name__ == "__main__":
    main()
