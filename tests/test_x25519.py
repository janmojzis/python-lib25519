'''
x25519 test
'''

from lib25519 import x25519


def test_x25519() -> None:
    '''
    x25519 test
    '''

    pk1, sk1 = x25519.keypair()
    pk2, sk2 = x25519.keypair()
    k1 = x25519.dh(pk1, sk2)
    k2 = x25519.dh(pk2, sk1)
    assert k1 == k2
