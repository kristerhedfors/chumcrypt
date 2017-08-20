#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
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
from itertools import imap

__all__ = ['ChumCipher']


def hmacsha256(key, msg=None):
    return hmac.new(key, msg, sha256)


class utils(object):
    '''
    Class for collecting entropy from within python environment in a
    portable manner.
    '''
    _entropy_pool = None

    @classmethod
    def _entropy_from_obj(cls, o):
        '''
        Collect entropy from all attributes of an object.
        '''
        from operator import attrgetter as ag
        h = sha256()
        #                                 .--.
        #                                (._=.\
        #                                `- - j)
        #                                 \- /
        #                                ._| |__
        #                               (/      \
        map(h.update, imap(repr, ag(*dir(o))(o)))
        #                            .__)|  " /\, \
        #                           //, _/ , (_/ /
        #                          /"        / ('
        #                          \  \___\/ \\`
        #                           \  |   \|  |^,
        #                            \ |    \  |)
        #                             ) \    ._/
        #                            /  )
        return h.digest()

    @classmethod
    def _entropy_gather(cls, extra=''):
        '''
        Collect entropy from various sources on the system.
        '''
        rand = random.SystemRandom()
        h = sha256()
        objlist = range(32) + globals().values() + locals().values()
        rand.shuffle(objlist)
        map(h.update, imap(cls._entropy_from_obj, objlist))
        h.update(os.urandom(64))
        h.update(str(time.time()))
        h.update(extra)
        return h.digest()

    @classmethod
    def random(cls, n=32):
        '''
        Return 32 bytes of freshly generated entropy.
        '''
        res = ''
        pool = cls._entropy_pool
        if not pool:
            pool = cls._entropy_gather()
        while len(res) < n:
            e = sha256(pool).digest()
            pool = hmacsha256(e, pool).digest()
            res += e
        cls._entropy_pool = pool
        return res[:n]

    @classmethod
    def gen_key(cls, iterations=10**6):
        '''
        Generate a key suitable to use with SecretBox.
        Lower `iterations` to something like 10**4 if speed is a concern.
        '''
        key = cls.random(64)
        salt = cls.random(64)
        key = hashlib.pbkdf2_hmac('sha256', key, salt, iterations)
        return key


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
    '''
    ChumCipher provides a poor-man's stream cipher based upon
    cryptographic hashing algorithms available in the Python 2
    standard library.

    >>> key = 'k' * 32
    >>> nonce = 'n' * 16
    >>> cc = ChumCipher(key, nonce)
    >>> chum = cc._read_chum(20)
    >>> print(chum)
    t\x9c^\xbbj`\x9a\x89\x8f\xbbq\xc7#\xd6:F\x1a#\x0c\x12

    >>> key = utils.gen_key()
    >>> nonce = utils.random(16)
    >>> msg = 'all your secret are belong to US'
    >>> encryptor = ChumCipher(key, nonce, msg)
    >>> decryptor = ChumCipher(key, nonce, encryptor)
    >>> decryptor.read(len(msg)) == msg
    True

    '''
    def __init__(self, key, nonce=None, msg_or_file=None):
        assert len(key) == 32
        assert len(nonce) >= 16
        if type(msg_or_file) in (str, unicode):
            msg_or_file = StringIO.StringIO(msg_or_file)
        self._key = key
        self._nonce = nonce
        self._f = msg_or_file
        self._counter = 0
        self._buffer = ''

    def _hmac(self, msg):
        return hmacsha256(self._key, msg).digest()

    def _inc(self):
        '''
        grow buffer with one block
        '''
        block_id = struct.pack('Q', self._counter)
        chum = self._hmac(self._nonce + block_id)
        self._buffer += chum
        self._counter += 1

    def _read_chum(self, n):
        '''
        return n bytes from buffer
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

    def _xor(self, s1, s2):
        '''
        xor two strings
        '''
        assert len(s1) == len(s2)
        x = [chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2)]
        return ''.join(x)

    def read(self, n):
        '''
        read and xor n bytes
        '''
        buf = self._f.read(n)
        chum = self._read_chum(len(buf))
        return self._xor(buf, chum)


class SecretBox(object):
    '''
    SecretBox is similar to nacl.secret.SecretBox.
    It allows for a poor man's pure python, no-dependencies
    authenticated symmetric-key encryption based upon SHA256.

    >>> import chumcrypt
    >>> key = chumcrypt.utils.gen_key()
    >>> box = chumcrypt.SecretBox(key)
    >>> msg = 'all your secret are belong to US'
    >>> encrypted = box.encrypt(msg)
    >>> box.decrypt(encrypted) == msg
    True
    '''
    def __init__(self, key, cipher_cls=ChumCipher):
        self._seal_key = hmacsha256(key, "seal").digest()
        self._cipher_key = hmacsha256(key, "cipher").digest()
        self._cipher_cls = cipher_cls

    def _hmac(self, msg):
        return hmacsha256(self._seal_key, msg).digest()

    def _new_cipher(self, nonce, msg):
        return self._cipher_cls(self._cipher_key, nonce, msg)

    def seal(self, content):
        '''
        Append a HMACSHA256-digest of `content`, created using the `key`
        passed to SecretBox constructor.
        Returns content with the digest appended.
        '''
        sealed = (content + self._hmac(content))
        return sealed

    def unseal(self, sealed):
        '''
        Validate and remove the SHA256HMAC digest at the end of `sealed`.
        Returns content without the signature hash.
        Raises AssertionError if the digest is invalid.
        '''
        assert len(sealed) >= 32
        content, sig = sealed[:-32], sealed[-32:]
        assert self._hmac(content) == sig
        return content

    def encrypt(self, msg, nonce=None):
        '''
        Encrypt and seal msg with the `key` supplied to the constructor.
        Returns sealed ciphertext.
        '''
        if not nonce:
            nonce = utils.random(16)
        assert len(nonce) == 16
        cipher = self._new_cipher(nonce, msg)
        ciphertext = cipher.read(len(msg))
        package = self.seal(nonce + ciphertext)
        return package

    def decrypt(self, package):
        '''
        Encrypt and seal msg with the `key` supplied to the constructor.
        Returns the validated and decrypted plaintext.
        Raises AssertionError if signature validation fails.
        '''
        content = self.unseal(package)
        assert len(content) >= 16
        nonce, ciphertext = content[:16], content[16:]
        crypt = self._new_cipher(nonce, ciphertext)
        msg = crypt.read(len(ciphertext))
        return msg


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
