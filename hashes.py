import regex


def base64_to_b(s: str) -> str:
    return s.replace('+', '.')


def base64_to_a(s: str) -> str:
    return s.replace('.', '+')


def is_sha512(s: str) -> bool:
    return True if regex.match(r'^\$6\$', s) else False


def is_argon2(s: str) -> bool:
    return True if regex.match(r'^\$argon2', s) else False


def is_sha1(s: str) -> bool:
    return True if regex.match(r'^\$sha1\$', s) else False


class PBKDF(object):
    _pbkdf_regex = regex.compile(r'^\$pbkdf2[-_]sha256\$'
                                 r'(?P<iterations>\d+)\$'
                                 r'(?P<salt>[a-zA-Z0-9/.+=]+)\$'
                                 r'(?P<digest>[a-zA-Z0-9/.+=]+)$')
    _sha_regex = regex.compile(r'^sha256:'
                               r'(?P<iterations>\d+):'
                               r'(?P<salt>[a-zA-Z0-9/=+.]+):'
                               r'(?P<digest>[a-zA-Z0-9/=+.]+)$')
    _pbkdf_repl = r'$pbkdf2-sha256$\g<iterations>$\g<salt>$\g<digest>'
    _sha_repl = r'sha256:\g<iterations>:\g<salt>:\g<digest>'

    @classmethod
    def is_pbkdf(cls, s: str) -> bool:
        return cls._sha_regex.match(s) or cls._pbkdf_regex.match(s)

    def __init__(self, s):
        if self._pbkdf_regex.match(s):
            self.pbkdf_value = s
            self.sha_value = self._pbkdf_regex.sub(self._sha_repl,
                                                   base64_to_a(s))
        elif self._sha_regex.match(s):
            self.pbkdf_value = self._sha_regex.sub(self._pbkdf_repl,
                                                   base64_to_b(s))
            self.sha_value = s
        else:
            raise ValueError


def dehexify(s: str) -> str:
    match = regex.match(r'^\$HEX\[([a-fA-F0-9]+)\]$', s)
    return bytes.fromhex(match.group(1)).decode() if match else s

