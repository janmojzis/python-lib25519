'''
random data ed25519 test
'''

import os
from secrets import randbelow
from lib25519 import ed25519


def test_ed25519() -> None:
    '''
    random data ed25519 test
    '''

    pk, sk = ed25519.keypair()
    m1 = os.urandom(128 + randbelow(128))
    sm = ed25519.sign(m1, sk)
    m2 = ed25519.open(sm, pk)
    assert m1 == m2

    # replace every byte in a signed message and check if open fails
    for i in range(len(sm)):
        modifiedsm = bytearray(sm)
        modifiedsm[i] = (modifiedsm[i] + 1 + randbelow(255)) % 256
        modifiedsm = bytes(modifiedsm)
        try:
            modifiedm = ed25519.open(modifiedsm, pk)
        except ValueError:
            pass
        else:
            raise ValueError('message forgery not detected !!!')
