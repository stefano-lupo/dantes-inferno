import base64
import codecs
import json
from Crypto.Cipher import AES
from typing import *
from unipath import Path

from as5_makeinferno import pwds_shares_to_secret
from hashes import *

BALL_PATH = Path('00092_blottn.as5')
SECRETS_PATH = Path('00092_blottn.secrets')
POT_PATH = Path('potfile')

BallType = Dict
PotType = List[Tuple[str, str]]


def get_pot(path: Path = POT_PATH) -> PotType:
    potlines = path.read_file().splitlines()
    potlines = [l.rsplit(':', 1) for l in potlines]
    potlines = [l for l in potlines if len(l) == 2 and not isinstance(l, str)]
    potlines = [(PBKDF(h).pbkdf_value, p) if PBKDF.is_pbkdf(h) else (h, p)
                for h, p in potlines]
    potlines = [(h, dehexify(p)) for h, p in potlines]
    return potlines


def get_ball(path: Path = BALL_PATH,
             secrets_path: Path = SECRETS_PATH,
             level: int = -1) -> BallType:
    ball = path.read_file()
    ball = json.loads(ball)
    if SECRETS_PATH.exists():
        secrets = secrets_path.read_file().splitlines()
        for secret in secrets[:level]:
            ball = descend(ball, secret)
    return ball


def get_cracked_passwords(ball: BallType,
                          pot: PotType) -> List[Tuple[int, str]]:
    cracked = []
    for i, h in enumerate(ball['hashes']):
        for ph, pp in pot:
            if h in ph:
                cracked.append((i, pp))
    return cracked


def get_secret(ball: BallType, pot: PotType) -> str:
    cracked = get_cracked_passwords(ball, pot)
    return pwds_shares_to_secret([p.encode() for i, p in cracked],
                                 [i for i, p in cracked],
                                 ball['shares'])


def decrypt_cipher(ball: BallType, secret: str):
    def decrypt(enc: bytes, key: bytes) -> bytes:
        def unpad(s: bytes) -> bytes:
            return s[:-ord(s[len(s) - 1:])]

        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

    secret = secret.zfill(32)
    if len(secret) % 2 != 0:
        secret = '0' + secret
    secret = codecs.decode(secret, 'hex')
    return decrypt(ball['ciphertext'], secret)


def descend(ball: BallType, secret: str) -> BallType:
    return json.loads(decrypt_cipher(ball, secret))
