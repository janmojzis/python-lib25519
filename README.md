Python wrapper around implementation of the X25519 and Ed25519 cryptosystems

### X25519

Import library:

    from lib25519 import x25519

Key generation:

    alicepk, alicesk = x25519.keypair()
    bobpk, bobsk = x25519.keypair()

Shared-secret generation:

    bobk = x25519.dh(alicepk, bobsk)
    alicek = x25519.dh(bobpk, alicesk)

Check:

    assert (alicek == bobk)
    
### Ed25519

Import library:

    from lib25519 import ed25519

Key generation:

    alicepk, alicesk = ed25519.keypair()

Signature generation:

    m = b'Hello'
    sm = ed25519.sign(m, alicesk)

Signature verification and message recovery:

    recoveredm = ed25519.open(sm, alicepk)

Check:

    assert (m == recoveredm)
