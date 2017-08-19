#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
#
# TODO
# + key expansion
# * split into hmac and crypt key
# + native entropy
# + clarify entropy, make it mean entropy as a random source
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

__all__ = ['ChumCipher']


class EntropyMixin(object):
    ''' Class for collecting entropy from within python environment in a
    portable manner.
    '''

    _entropy_pool = None

    @classmethod
    def _entropy_from_obj(cls, o):
        from operator import attrgetter as ag
        #                        .--.
        #                       (._=.\
        #                       `- - j)
        #                        \- /
        #                       ._| |__
        #                      (/      \
        data = map(str, ag(*dir(o))(o))
        #                   .__)|  " /\, \
        #                  //, _/ , (_/ /
        #                 /"        / ('
        #                 \  \___\/ \\`
        #                  \  |   \|  |^,
        #                   \ |    \  |)
        #                    ) \    ._/
        #                   /  )
        return hashlib.sha512(''.join(data)).digest()

    @classmethod
    def _entropy_gather(cls, extra=''):
        # V
        rand = random.SystemRandom()
        h = hashlib.sha512()
        # C
        objlist = ["?"] + range(64) + globals().values() + locals().values()
        rand.shuffle(objlist)
        map(h.update, [cls._entropy_from_obj(o) for o in objlist])
        h.update(os.urandom(64))
        h.update(str(time.time()))
        h.update(extra)
        return h.digest()

    @classmethod
    def get_entropy(cls):
        ''' Return 64 bytes of fresh entropy. May be OK to use as key directly.
        '''
        if not cls._entropy_pool:
            cls._entropy_pool = cls._entropy_gather()
        e = hashlib.sha512(cls._entropy_pool).digest()
        h = hmac.new(e, cls._entropy_pool, hashlib.sha512)
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
    DIGESTMOD = hashlib.sha256
    HASH_NAME = DIGESTMOD().name
    KEY_SIZE = DIGESTMOD().digestsize
    KEYGEN_ITERATIONS = 10**4
    MIN_IV_LEN = 16

    def __init__(self, key='', nonce='', entropy='', digestmod=DIGESTMOD):
        # A
        assert len(key) == self.KEY_SIZE
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

    def _hmac(self, msg):
        return hmac.new(self._key, msg, digestmod=self._digestmod).digest()

    def _inc(self):
        ''' grow buffer with one block
        '''
        # A
        assert self._buffer == ''
        # V
        entropy = self._entropy
        block_id = struct.pack('I', self._counter)
        nonce = self._nonce
        # C
        chum = self._hmac(entropy + nonce + block_id)
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
                self._inc()
            res += curr
            n -= len(curr)
        return res


class ChumCrypt(ChumCipher, EntropyMixin):

    @classmethod
    def new_key(cls):
        key = cls.get_entropy()
        salt = cls.get_entropy()
        key = hashlib.pbkdf2_hmac(cls.HASH_NAME, key, salt,
                                  cls.KEYGEN_ITERATIONS)
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
        ''' read and xor n bytes from fa and fb
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
        # V
        self._key = key
        self._crypt_cls = crypt_cls

    def _new_crypt(self, f, key, nonce, **kw):
        return self._crypt_cls(f=f, key=key, nonce=nonce, **kw)

    def new_nonce(self):
        return ChumCrypt.get_entropy()[:self.NONCE_LEN]

    def seal(self, crypt, content):
        sealed = (content + crypt._hmac(content))
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
        crypt = self._new_crypt(f, key, nonce)
        ciphertext = crypt.read(size)
        content = nonce + ciphertext + crypt._hmac(nonce + ciphertext)
        assert crypt.read(1) == ''
        return content


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
