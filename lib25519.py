from ctypes.util import find_library as _find_library
from typing import Tuple as _Tuple
import ctypes as _ct

_lib = _ct.CDLL(_find_library('25519'))


def _check_input(x, xlen, name):
    if not isinstance(x, bytes):
        raise TypeError(f'{name} must be bytes')
    if xlen != -1 and xlen != len(x):
        raise ValueError(f'{name} length must have exactly {xlen} bytes')


class x25519:
    PUBLICKEYBYTES = 32
    SECRETKEYBYTES = 32
    BYTES = 32

    def keypair(self) -> (bytes, bytes):
        '''
        Keypair - randomly generates secret key and corresponding public key.
        Returns:
            pk (bytes): public key
            sk (bytes): sectet key
        '''
        pk = _ct.create_string_buffer(self.PUBLICKEYBYTES)
        sk = _ct.create_string_buffer(self.SECRETKEYBYTES)
        c_keypair = getattr(_lib, 'lib25519_dh_x25519_keypair')
        c_keypair.argtypes = [_ct.c_char_p, _ct.c_char_p]
        c_keypair.restype = None
        c_keypair(pk, sk)
        return pk.raw, sk.raw

    def dh(self, pk: bytes, sk: bytes) -> (bytes):
        '''
        Diffe-Helman - computes shared secret.
        Parameters:
            pk (bytes): public key
            sk (bytes): secret key
        Returns:
            k (bytes): shared secret
        '''
        _check_input(pk, self.PUBLICKEYBYTES, 'pk')
        _check_input(sk, self.SECRETKEYBYTES, 'sk')
        c_enc = getattr(_lib, 'lib25519_dh_x25519')
        c_enc.argtypes = [_ct.c_char_p, _ct.c_char_p, _ct.c_char_p]
        c_enc.restype = None
        k = _ct.create_string_buffer(self.BYTES)
        c_enc(k, pk, sk)
        return k.raw


x25519 = x25519()


class ed25519:
    PUBLICKEYBYTES = 32
    SECRETKEYBYTES = 64
    BYTES = 64

    def keypair(self) -> (bytes, bytes):
        '''
        Keypair - randomly generates secret key and corresponding public key.
        Returns:
            pk (bytes): public key
            sk (bytes): sectet key
        '''
        pk = _ct.create_string_buffer(self.PUBLICKEYBYTES)
        sk = _ct.create_string_buffer(self.SECRETKEYBYTES)
        c_keypair = getattr(_lib, 'lib25519_sign_ed25519_keypair')
        c_keypair.argtypes = [_ct.c_char_p, _ct.c_char_p]
        c_keypair.restype = None
        c_keypair(pk, sk)
        return pk.raw, sk.raw

    def sign(self, m: bytes, sk: bytes) -> bytes:
        '''
        Signature generation - signs the message 'm' using secret key 'sk' and returns signed message 'sm'.
        Parameters:
            m (bytes): message
            sk (bytes): sectet key
        Returns:
            sm (bytes): signed message
        '''
        _check_input(m, -1, 'm')
        _check_input(sk, self.SECRETKEYBYTES, 'sk')
        mlen = _ct.c_longlong(len(m))
        smlen = _ct.c_longlong(0)
        sm = _ct.create_string_buffer(len(m) + self.BYTES)
        m = _ct.create_string_buffer(m)
        sk = _ct.create_string_buffer(sk)
        c_sign = getattr(_lib, 'lib25519_sign_ed25519')
        c_sign.argtypes = [_ct.c_char_p, _ct.POINTER(
            _ct.c_longlong), _ct.c_char_p, _ct.c_longlong, _ct.c_char_p]
        c_sign.restype = None
        c_sign(sm, _ct.byref(smlen), m, mlen, sk)
        return sm.raw[:smlen.value]

    def open(self, sm: bytes, pk: bytes) -> bytes:
        '''
        Signature verification and message recovery - verifies the signed message 'sm' using public key 'pk', and then returns the verified message 'm'.
        Parameters:
            sm (bytes): signed message
            pk (bytes): public key
        Returns:
            m (bytes): message
        '''
        _check_input(sm, -1, 'sm')
        _check_input(pk, self.PUBLICKEYBYTES, 'pk')
        smlen = _ct.c_longlong(len(sm))
        m = _ct.create_string_buffer(len(sm))
        mlen = _ct.c_longlong(0)
        pk = _ct.create_string_buffer(pk)
        c_open = getattr(_lib, 'lib25519_sign_ed25519_open')
        c_open.argtypes = [_ct.c_char_p, _ct.POINTER(
            _ct.c_longlong), _ct.c_char_p, _ct.c_longlong, _ct.c_char_p]
        c_open.restype = _ct.c_int
        if c_open(m, _ct.byref(mlen), sm, smlen, pk):
            raise Exception('open failed')
        return m.raw[:mlen.value]


ed25519 = ed25519()

if __name__ == '__main__':

    import os

    # X25519
    print(f'testing {x25519}')
    pk1, sk1 = x25519.keypair()
    pk2, sk2 = x25519.keypair()
    k1 = x25519.dh(pk1, sk2)
    k2 = x25519.dh(pk2, sk1)
    assert (k1 == k2)

    # Ed25519
    print(f'testing {ed25519}')
    pk, sk = ed25519.keypair()
    m1 = os.urandom(128)
    sm = ed25519.sign(m1, sk)
    m2 = ed25519.open(sm, pk)
    assert (m1 == m2)

    print("OK")