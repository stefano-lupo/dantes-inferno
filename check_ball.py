#!/usr/bin/python

import json

from inferno import *


def main():
    ball = get_ball()
    pot = get_pot()
    if len(get_cracked_passwords(ball, pot)) < 2:
        print('Not enough passwords cracked yet to even try')
        return
    secret = get_secret(ball, pot)
    cipher = decrypt_cipher(ball, secret)
    print(cipher[:40])
    try:
        new_ball = json.loads(cipher)
        print(secret)
        print('Next level reached!')
    except (ValueError, UnicodeDecodeError):
        print('{:d} passwords but no can do'
              .format(len(get_cracked_passwords(ball, pot))))


if __name__ == '__main__':
    main()
