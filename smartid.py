from collections import namedtuple

import pyasice
import requests
import os
import base64
import hashlib
import struct
from oscrypto.asymmetric import load_certificate
from oscrypto.asymmetric import Certificate as OsCryptoCertificate
from asn1crypto.cms import Certificate as Asn1CryptoCertificate

certificate_level = 'QUALIFIED'
country = 'EE'
hash_type = 'SHA256'
id_code = '30303039914'
baseURL = "https://sid.demo.sk.ee/smart-id-rp/v2"

random_bytes = os.urandom(64)
hash_value = hashlib.sha256(random_bytes).digest()
hash_value_b64 = base64.b64encode(hash_value).decode()
data = {
    "certificateLevel": certificate_level,
    "hashType": hash_type,
    "hash": hash_value_b64,
    "allowedInteractionsOrder": [
        {
            "type": "verificationCodeChoice",
            "displayText60": "Up to 60 characters of text here.."
        },
        {
            "type": "displayTextAndPIN",
            "displayText60": "Up to 60 characters of text here.."
        }
    ],
    # Don't use nonce to so we can rely on idempotent behaviour
    #
    # From the docs:
    #
    # Whenever a RP session creation request (POST to certificatechoice/, signature/, authentication/) is
    # repeated inside a given timeframe with exactly the same parameters, session ID of an existing
    # session can be returned as a result.
    #
    # This allows to retry RP POST requests in case of communication errors. Retry timeframe is 15 seconds.
    #
    # When requestor wants, it can override the idempotent behaviour inside of this timeframe using an
    # optional "nonce" parameter present for all POST requests. Normally, that parameter can be omitted.
    # 'nonce': None,
    'relyingPartyUUID': '00000000-0000-0000-0000-000000000000',
    'relyingPartyName': 'DEMO',
}


class CertificateHolderInfo:
    def __init__(self, given_name, surname, id_code, country, asn1_certificate):
        self.given_name: str = given_name
        self.surname: str = surname
        self.id_code: str = id_code
        self.country: str = country
        self.asn1_certificate: "Asn1CryptoCertificate" = asn1_certificate

    def __str__(self):
        return f"{self.given_name=}\n{self.surname=}\n{self.id_code=}\n{self.country=}\n{self.asn1_certificate=}\n"

    @classmethod
    def from_certificate(cls, cert: "Union[bytes, Asn1CryptoCertificate, OsCryptoCertificate]"):
        """
        Get personal info from an oscrypto/asn1crypto Certificate object

        For a closer look at where the attributes come from:
        asn1crypto.x509.NameType
        """
        if isinstance(cert, bytes):
            cert = load_certificate(cert)
        cert: "Asn1CryptoCertificate" = getattr(cert, "asn1", cert)
        subject = cert.subject.native

        # ID codes usually given as PNO{EE,LT,LV}-XXXXXX.
        # LV ID codes contain a dash so we need to be careful about it.
        id_code = subject["serial_number"]
        if id_code.startswith("PNO"):
            prefix, id_code = id_code.split("-", 1)  # pylint: disable=unused-variable

        return cls(
            country=subject["country_name"],
            id_code=id_code,
            given_name=subject["given_name"],
            surname=subject["surname"],
            asn1_certificate=cert,
        )


def get_verification_code(hash_value):
    """Compute Smart-ID verification code from a hash

    Verification Code is computed with: `integer(SHA256(hash)[-2:-1]) mod 10000`

    1. Take SHA256 result of hash_value
    2. Extract 2 rightmost bytes from it
    3. Interpret them as a big-endian unsigned short
    4. Take the last 4 digits in decimal

    Note: SHA256 is always used, e.g. the algorithm used when generating the hash does not matter

    based on https://github.com/SK-EID/smart-id-documentation#612-computing-the-verification-code
    """
    digest = hashlib.sha256(hash_value).digest()
    raw_value = struct.unpack(">H", digest[-2:])[0] % 10000

    return f"{raw_value:04}"


class AuthenticationResult:
    country: str
    id_code: str
    given_name: str
    surname: str
    certificate_b64: str


AuthenticateStatusResult = namedtuple(
    "AuthenticateStatusResult",
    [
        "document_number",
        "certificate",  # DER-encoded certificate
        "certificate_b64",  # Base64-encoded DER-encoded certificate
        "certificate_level",
    ],
)

r = requests.Session()

res = r.post(url=f'{baseURL}/authentication/etsi/PNO{country}-{id_code}', json=data)
print(res.json())
print(res.status_code)

print(get_verification_code(hash_value))

for i in range(10):
    res2 = r.get(url=f"{baseURL}/session/{res.json()['sessionID']}", params={'timeoutMs': 10000})
    print(res2.status_code)
    if res2.json()['state'] == 'COMPLETE' and res2.json()['result']['endResult'] != 'OK':
        raise Exception(res2.json()['result']['endResult'])
    else:
        break

data = res2.json()
cert_value = base64.b64decode(data["cert"]["value"])
signature_value = base64.b64decode(data["signature"]["value"])

try:
    pyasice.verify(cert_value, signature_value, hash_value, 'sha256', prehashed=True)
except pyasice.SignatureVerificationError as e:
    raise e

ci = CertificateHolderInfo.from_certificate(cert_value)

print(ci)
