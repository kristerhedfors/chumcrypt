#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
#
#
import unittest
import logging
# import hashlib
# import hmac
# import struct
import StringIO
from itertools import imap
from hashlib import sha256

from chumcrypt import ChumCipher
from chumcrypt import SecretBox
from chumcrypt import utils


# logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(': ***ChumCipher*** :')


def debug(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.debug('  ' + msg)


def warn(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.warn('  ' + msg)


class Test_ChumCipher(unittest.TestCase):

    def test_basics(self):
        f = StringIO.StringIO('perkele')
        key = utils.gen_key()
        assert len(key) == 32
        nonce = utils.random(16)
        cc = ChumCipher(key, nonce, f)
        print(repr(cc.read(29)))

    def test_longer_irregular_read_lengths(self):
        key = 'a' * 32
        nonce = 'n' * 16
        cc = ChumCipher(key, nonce)
        n = 0
        while n < 2000:
            assert len(cc._read_chum(n)) == n
            n += 11


class Test_SecretBox(unittest.TestCase):

    def test_basics(self):
        key = utils.gen_key()
        box = SecretBox(key)
        nonce = utils.random(16)
        package = box.encrypt('P' * 32, 'N' * 16)
        pt = box.decrypt(package)
        assert pt == 'P' * 32
        for i in xrange(100):
            plaintext = utils.random(i)
            nonce = 'N' * 16
            package = box.encrypt(plaintext, nonce)
            assert plaintext == box.decrypt(package)

    def test_seal(self):
        key = 'K' * 32
        box = SecretBox(key)
        msg = 'hello chum'
        smsg = box.seal(msg)
        assert box.unseal(smsg) == msg


class Test_SecretBox2(unittest.TestCase):

    def _crypt_decrypt(self, key=None, nonce=None):
        key = key or utils.random(32)  # faster
        nonce = key or utils.random(16)  # faster

    def _recursive_boxes(self, keygen, n):
        boxes = []
        keys = [k for k in keygen]
        print keys
        packages = []
        p = None
        #
        # Create n packages where package[n-1] equals the plaintext
        # of package[n].
        #
        for i in xrange(n):
            box = SecretBox(keys[i])
            if i == 0:
                msg = 'Welcome! how did you get here?'
            else:
                msg = packages[i-1]
            p = box.encrypt(msg)
            packages.append(p)
        keys.reverse()
        packages.reverse()
        #
        # Decrypt each package p in packages. That is, n decrypt operations
        # for the first package, (n-1) for the second and so forth.
        # Assert success after each completed package series.
        #
        for i in xrange(len(packages)):
            p = packages[i]
            for key in keys[i:]:
                p = SecretBox(key).decrypt(p)
            assert p == 'Welcome! how did you get here?'
        assert p == 'Welcome! how did you get here?'
        print(p)

    def test_recursive_boxes(self):
        n = 20
        keygen = imap(lambda i: sha256(str(i)).digest(), xrange(n))
        self._recursive_boxes(keygen, n)







if __name__ == '__main__':
    unittest.main()
