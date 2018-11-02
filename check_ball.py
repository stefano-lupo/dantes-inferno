#!/usr/bin/python

import json

from inferno import *

if __name__ == '__main__':
    ball = get_ball()
    pot = get_pot()
    secret = get_secret(ball, pot)
    cipher = decrypt_cipher(ball, secret)
    print(cipher[:40])
    try:
        new_ball = json.loads(cipher)
        print(secret)
        print('Next level reached!')
    except (ValueError, UnicodeDecodeError):
        print('{:d} passwords, can\' crack yet'.format(len(
            get_cracked_passwords(ball, pot))))
