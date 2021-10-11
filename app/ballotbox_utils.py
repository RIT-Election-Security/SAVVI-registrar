from base64 import b64decode, b64encode
from cryptography.fernet import Fernet
from dataclasses import dataclass
from json import dumps, loads
from sys import getdefaultencoding


@dataclass
class BallotDetails():
    ballot_style: str
    voter_number: int


def dump_encrypt_encode_dict(dictionary: dict, key: bytes) -> str:
    """
    Dump, encrypt, and base64 encode dict.

    Args:
        dictionary: dictionary object
        key: shared Fernet key
    Returns:
        Base64 encoded string of encrypted dictionary
    """
    dumped = dumps(dictionary)
    encrypted = Fernet(key).encrypt(bytes(dumped, encoding=getdefaultencoding()))
    encoded = b64encode(encrypted).decode()
    return encoded


def decode_decrypt_load_dict(string: str, key: bytes) -> dict:
    """
    Base64 decode, decrypt, and load dict.
    
    Args:
        string: base64 encoded string
        key: shared Fernet key
    Return:
        Loaded dictionary
    """
    decoded = b64decode(string)
    decrypted = Fernet(key).decrypt(decoded)
    loaded = loads(decrypted)
    return loaded


def generate_ballot_details_token(ballot_details: BallotDetails, token_id: str, key: bytes) -> str:
    """
    Make ballot details dictionary, dump to json string, encrypt and base64 encode
    Adds token's ID to database

    Args:
        ballot_details: BallotDetails object with style and voter number
        key: valid Fernet key shared with ballotbox
    Returns:
        base64 encoded, encrypted string of ballot details as JSON
    """
    dictified = {
            "ballot_style": ballot_details.ballot_style,
            "token_id": token_id,
            "voter_number": ballot_details.voter_number
        }
    return dump_encrypt_encode_dict(dictified, key)
