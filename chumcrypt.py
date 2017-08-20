#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
#
# TODO
# + key expansion
# + split into hmac and crypt key
# + native entropy
# * (tool able to validate signatures of its components over https)
#
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
import time
import StringIO
import random
from hashlib import sha256


__all__ = ['ChumCipher']


def hmacsha256(key, msg=None):
    return hmac.new(key, msg, sha256)


class EntropyMixin(object):
    ''' Class for collecting entropy from within python environment in a
    portable manner.
    '''
    _entropy_pool = None

    @classmethod
    def _entropy_from_obj(cls, o):
        from operator import attrgetter as ag
        #                         .--.
        #                        (._=.\
        #                        `- - j)
        #                         \- /
        #                        ._| |__
        #                       (/      \
        data = map(repr, ag(*dir(o))(o))
        #                    .__)|  " /\, \
        #                   //, _/ , (_/ /
        #                  /"        / ('
        #                  \  \___\/ \\`
        #                   \  |   \|  |^,
        #                    \ |    \  |)
        #                     ) \    ._/
        #                    /  )
        return sha256(''.join(data)).digest()

    @classmethod
    def _entropy_gather(cls, extra=''):
        # V
        rand = random.SystemRandom()
        h = sha256()
        # C
        objlist = range(32) + globals().values() + locals().values()
        rand.shuffle(objlist)
        map(h.update, [cls._entropy_from_obj(o) for o in objlist])
        h.update(os.urandom(64))
        h.update(str(time.time()))
        h.update(extra)
        return h.digest()

    @classmethod
    def get_entropy(cls):
        ''' Return 32 bytes of fresh entropy.
        '''
        if not cls._entropy_pool:
            cls._entropy_pool = cls._entropy_gather()
        e = sha256(cls._entropy_pool).digest()
        h = hmacsha256(e, cls._entropy_pool)
        cls._entropy_pool = h.digest()
        return e


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
    KEYGEN_ITERATIONS = 10**4

    def __init__(self, key='', nonce=''):
        assert len(key) == 32
        assert len(nonce) >= 16
        self._key = key
        self._nonce = nonce
        self._counter = 0
        self._buffer = ''

    def _hmac(self, msg):
        return hmacsha256(self._key, msg).digest()

    def _inc(self):
        ''' grow buffer with one block
        '''
        block_id = struct.pack('Q', self._counter)
        chum = self._hmac(self._nonce + block_id)
        self._buffer += chum
        self._counter += 1

    def read_chum(self, n):
        ''' return n bytes from buffer
        '''
        res = ''
        while n > 0:
            blsize = min(n, 32)
            if len(self._buffer) < blsize:
                self._inc()
            block, self._buffer = self._buffer[:blsize], self._buffer[blsize:]
            res += block
            n -= blsize
        return res


class ChumCrypt(ChumCipher, EntropyMixin):

    @classmethod
    def new_key(cls):
        key = cls.get_entropy()
        salt = cls.get_entropy()
        key = hashlib.pbkdf2_hmac('sha256', key, salt, cls.KEYGEN_ITERATIONS)
        return key

    def __init__(self, f, **kw):
        self._f = f
        super(ChumCrypt, self).__init__(**kw)

    def _xor(self, s1, s2):
        ''' xor two strings
        '''
        assert len(s1) == len(s2)
        x = [chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2)]
        return ''.join(x)

    def read(self, n):
        ''' read and xor n bytes
        '''
        buf = self._f.read(n)
        chum = self.read_chum(len(buf))
        return self._xor(buf, chum)


class SecretBox(object):

    @classmethod
    def new_key(cls):
        return ChumCrypt.new_key()

    NONCE_LEN = 16

    def __init__(self, key, crypt_cls=ChumCrypt):
        self._hmac_key = hmacsha256(key, "hmac").digest()
        self._crypt_key = hmacsha256(key, "crypt").digest()
        self._crypt_cls = crypt_cls

    def _hmac(self, msg):
        return hmacsha256(self._hmac_key, msg).digest()

    def _new_crypt(self, f, nonce, **kw):
        return self._crypt_cls(f=f, key=self._crypt_key, nonce=nonce, **kw)

    def new_nonce(self):
        return ChumCrypt.get_entropy()[:self.NONCE_LEN]

    def seal(self, content):
        sealed = (content + self._hmac(content))
        return sealed

    def unseal(self, sealed):
        assert len(sealed) >= 32
        content, sig = sealed[:-32], sealed[-32:]
        assert self._hmac(content) == sig
        return content

    def encrypt(self, msg, nonce=None):
        if not nonce:
            nonce = self.new_nonce()
        assert len(nonce) == self.NONCE_LEN
        f = StringIO.StringIO(msg)
        crypt = self._new_crypt(f, nonce)
        ciphertext = crypt.read(len(msg))
        package = self.seal(nonce + ciphertext)
        return package

    def decrypt(self, package):
        content = self.unseal(package)
        nonce_len = self.NONCE_LEN
        assert len(content) >= nonce_len
        nonce, ciphertext = content[:nonce_len], content[nonce_len:]
        f = StringIO.StringIO(ciphertext)
        crypt = self._new_crypt(f, nonce)
        msg = crypt.read(len(ciphertext))
        return msg


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
