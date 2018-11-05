#!/usr/bin/python

from inferno import *

ball = get_ball()
pot = get_pot()
secret = get_secret(ball, pot)
print(secret)
