if __name__ == '__main__':

    from lib25519 import ed25519
    import os

    pk, sk = ed25519.keypair()
    m1 = os.urandom(128)
    sm = ed25519.sign(m1, sk)
    m2 = ed25519.open(sm, pk)
    assert (m1 == m2)

    print('ed25519 OK')
