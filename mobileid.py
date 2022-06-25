import requests
import base64
import hashlib
import os
import struct
from collections import namedtuple
import pyasice
from oscrypto.asymmetric import load_certificate

id_code = '60001019906'
phone_number = '+37200000766'
baseURL = 'https://tsp.demo.sk.ee/mid-api'
random_bytes = os.urandom(64)
hash_value = hashlib.sha256(random_bytes).digest()
hash_value_b64 = base64.b64encode(hash_value).decode()

r = requests.Session()

res = r.post(
    url=f"{baseURL}/authentication",
    json={
        "nationalIdentityNumber": id_code,
        "phoneNumber": phone_number,
        "hashType": "sha256",
        "hash": hash_value_b64,
        "language": "ENG",
        # Casting to str to ensure translations are resolved
        "displayText": "a teeny-tiny message",  # NOTE: hard 20-char limit
        "displayTextFormat": "UCS-2",  # the other choice is GSM-7 which is 7-bit
        'relyingPartyUUID': '00000000-0000-0000-0000-000000000000',
        'relyingPartyName': 'DEMO',
    },
)

sessID = res.json()['sessionID']

AuthenticateResult = namedtuple(
    "AuthenticateResult",
    [
        "session_id",
        "hash_type",
        "hash_value",
        "hash_value_b64",
        "verification_code",
    ],
)


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


ar = AuthenticateResult(
    session_id=sessID,
    hash_value=hash_value,
    hash_value_b64=hash_value_b64,
    hash_type="sha256",
    verification_code=get_verification_code(hash_value),
)

print(ar)

for i in range(10):
    res2 = r.get(url=f"{baseURL}/authentication/session/{sessID}", params={'timeoutMs': 10000})
    if res2.json()['state'] == 'COMPLETE' and res2.json()['result'] != 'OK':
        raise Exception(res2.json()['result'])
    else:
        break

data = res2.json()
cert_value = base64.b64decode(data["cert"])
signature_value = base64.b64decode(data["signature"]["value"])

try:
    pyasice.verify(cert_value, signature_value, hash_value, 'sha256', prehashed=True)
except pyasice.SignatureVerificationError as e:
    raise e

ci = CertificateHolderInfo.from_certificate(cert_value)

print(ci)
