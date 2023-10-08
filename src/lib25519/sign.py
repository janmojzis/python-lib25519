from typing import Tuple as _Tuple
import ctypes as _ct
from ._lib import _lib, _check_input


class ed25519:
    PUBLICKEYBYTES = 32
    SECRETKEYBYTES = 64
    BYTES = 64

    def __init__(self) -> None:
        '''
        '''
        self._c_keypair = getattr(_lib, 'lib25519_sign_ed25519_keypair')
        self._c_keypair.argtypes = [_ct.c_char_p, _ct.c_char_p]
        self._c_keypair.restype = None
        self._c_sign = getattr(_lib, 'lib25519_sign_ed25519')
        self._c_sign.argtypes = [_ct.c_char_p, _ct.POINTER(
            _ct.c_longlong), _ct.c_char_p, _ct.c_longlong, _ct.c_char_p]
        self._c_sign.restype = None
        self._c_open = getattr(_lib, 'lib25519_sign_ed25519_open')
        self._c_open.argtypes = [_ct.c_char_p, _ct.POINTER(
            _ct.c_longlong), _ct.c_char_p, _ct.c_longlong, _ct.c_char_p]
        self._c_open.restype = _ct.c_int

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

    def sign(self, m: bytes, sk: bytes) -> bytes:
        '''
        Signature generation - signs the message 'm' using secret key 'sk' and returns signed message 'sm'.
        Parameters:
            m (bytes): message
            sk (bytes): secret key
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
        self._c_sign(sm, _ct.byref(smlen), m, mlen, sk)
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
        if self._c_open(m, _ct.byref(mlen), sm, smlen, pk):
            raise Exception('open failed')
        return m.raw[:mlen.value]


ed25519 = ed25519()
