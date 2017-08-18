#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
#
# Notation:
#   # A     =assertion section
#   # V     =local variable initiation section
#   # C     =Code section
#
import sys
import logging
import hashlib
import hmac
import struct
import os
import StringIO

__all__ = ['ChumCipher']


# logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(': ***ChumCipher*** :')


def debug(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.debug('  ' + msg)


def warn(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.warn('  ' + msg)


def main(*args):
    pass


class ChumCipher(object):
    ''' ChumCipher provides a poor-man's stream cipher based upon
    cryptographic hashing algorithms available in the Python 2
    standard library.
    '''
    DIGESTMOD=hashlib.sha256
    MIN_IV_LEN = 16

    def __init__(self, key='', nonce='', entropy='', digestmod=DIGESTMOD):
        # A
        if (len(nonce) + len(entropy)) < self.MIN_IV_LEN:
            err_msg = 'Not enough IV or entropy material: '
            err_msg += 'len(nonce) + len(entropy) < {0}'.format(
                self.MIN_IV_LEN)
            raise Exception(err_msg)
        # V
        self._key = key
        self._nonce = nonce
        self._entropy = entropy
        self._digestmod = digestmod
        self._state = ''
        self._counter = 0
        self._buffer = ''
        # C
        pass

    def hmac(self, msg):
        return hmac.new(self._key, msg, digestmod=self._digestmod).digest()

    def inc(self):
        ''' grow buffer with one block
        '''
        # A
        assert self._buffer == ''
        # V
        entropy = self._entropy
        block_id = struct.pack('I', self._counter)
        nonce = self._nonce
        # C
        chum = self.hmac(entropy + nonce + block_id)
        self._buffer += chum
        self._counter += 1

    def read_chum(self, n):
        ''' return n bytes from buffer
        '''
        # V
        res = ''
        # C
        while n > 0:
            batch_size = min(n, 16)
            curr, self._buffer = self._buffer[:batch_size], \
                                 self._buffer[batch_size:]
            if self._buffer == '' or len(curr) < batch_size:
                self.inc()
            res += curr
            n -= len(curr)
        return res


class ChumCrypt(ChumCipher):

    def __init__(self, f, **kw):
        self._f = f
        super(ChumCrypt, self).__init__(**kw)

    def xor(self, s1, s2):
        ''' xor two strings
        '''
        assert len(s1) == len(s2)
        x = [chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2)]
        return ''.join(x)

    def read(self, n):
        ''' read and xor n bytes from fa and fb
        '''
        buf = self._f.read(n)
        chum = self.read_chum(len(buf))
        return self.xor(buf, chum)


class SecretBox(object):

    NONCE_LEN = 16

    def __init__(self, key, crypt_cls=ChumCrypt):
        # V
        self._key = key
        self._crypt_cls = crypt_cls

    def new_nonce(self):
        return os.urandom(self.NONCE_LEN)

    def new_crypt(self, f, key, nonce, **kw):
        return self._crypt_cls(f=f, key=key, nonce=nonce, **kw)

    def seal(self, crypt, content):
        sealed = (content + crypt.hmac(content))
        return sealed

    def unseal(self, crypt, sealed):
        # A
        content, sig = sealed[:-self.NONCE_LEN], \
            sealed[-self.NONCE_LEN:]
        assert len(sealed) == len(content) + len(sig)
        assert crypt.seal(content) == sealed

    def encrypt(self, msg, nonce):
        # A
        if not nonce:
            nonce = self.new_nonce()
        if len(nonce) != self.NONCE_LEN:
            msg = 'Invalid nonce. Try using new_nonce().'
            raise Exception(msg)
        # V
        size = len(msg)
        key = self._key
        # C
        f = StringIO.StringIO(msg)
        crypt = self.new_crypt(f, key, nonce)
        ciphertext = crypt.read(size)
        content = nonce + ciphertext + crypt.hmac(nonce + ciphertext)
        assert crypt.read(1) == ''
        return ciphertext




if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
