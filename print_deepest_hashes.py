#!/usr/bin/python
import argparse

from inferno import *

parser = argparse.ArgumentParser()
parser.add_argument('--hashcat',
                    help='Convert to hashcat readable format',
                    action='store_true')
args = parser.parse_args()

ball = get_ball()
for h in ball['hashes']:
    h = PBKDF(h).sha_value if args.hashcat and PBKDF.is_pbkdf(h) else h
    print(h)
