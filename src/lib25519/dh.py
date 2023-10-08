from typing import Tuple as _Tuple
import ctypes as _ct
from ._lib import _lib, _check_input


class x25519:
    PUBLICKEYBYTES = 32
    SECRETKEYBYTES = 32
    BYTES = 32

    def __init__(self) -> None:
        '''
        '''

        self._c_keypair = getattr(_lib, 'lib25519_dh_x25519_keypair')
        self._c_keypair.argtypes = [_ct.c_char_p, _ct.c_char_p]
        self._c_keypair.restype = None
        self._c_dh = getattr(_lib, 'lib25519_dh_x25519')
        self._c_dh.argtypes = [_ct.c_char_p, _ct.c_char_p, _ct.c_char_p]
        self._c_dh.restype = None

    def keypair(self) -> _Tuple[bytes, bytes]:
        '''
        Keypair - randomly generates secret key and corresponding public key.
        Returns:
            pk (bytes): public key
            sk (bytes): secret key
        '''
        pk = _ct.create_string_buffer(self.PUBLICKEYBYTES)
        sk = _ct.create_string_buffer(self.SECRETKEYBYTES)
        self._c_keypair(pk, sk)
        return pk.raw, sk.raw

    def dh(self, pk: bytes, sk: bytes) -> bytes:
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
        k = _ct.create_string_buffer(self.BYTES)
        self._c_dh(k, pk, sk)
        return k.raw


x25519 = x25519()
