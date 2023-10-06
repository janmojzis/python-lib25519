from lib25519 import ed25519
import os


def test_ed25519():
    pk, sk = ed25519.keypair()
    m1 = os.urandom(128)
    sm = ed25519.sign(m1, sk)
    m2 = ed25519.open(sm, pk)
    assert (m1 == m2)

if __name__ == 'main':
    test_ed25519()
