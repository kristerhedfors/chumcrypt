#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
#
#
import unittest
import sys
import logging
# import hashlib
# import hmac
# import struct
import os
import StringIO

from chumcrypt import ChumCipher
from chumcrypt import ChumCrypt
from chumcrypt import SecretBox


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
        key = os.urandom(32)
        cs = ChumCipher(key=key, nonce='first_iv', entropy=os.urandom(20))
        for i in xrange(100):
            assert len(cs.read_chum(i)) == i
        print(repr(cs.read_chum(29)))
        assert len(cs.read_chum(41)) == 41

    def test_longer_irregular_read_lengths(self):
        key = 'a' * 32
        cs = ChumCipher(key=key, nonce='second_iv', entropy=os.urandom(20))
        n = 0
        while n < 2000:
            assert len(cs.read_chum(n)) == n
            n += 11

    def verify_param(self, name):
        pass

    def test_verify_key(self):
        pass


class Test_ChumCrypt(unittest.TestCase):

    def test_basics(self):
        f = StringIO.StringIO('perkele')
        key = ChumCrypt.new_key()
        cc = ChumCrypt(f=f, key=key, nonce='first_iv', entropy=os.urandom(20))
        print(repr(cc.read(29)))

    def test_longer_irregular_read_lengths(self):
        key = 'a' * 32
        cc = ChumCipher(key=key, nonce='second_iv', entropy=os.urandom(20))
        n = 0
        while n < 2000:
            assert len(cc.read_chum(n)) == n
            n += 11

    #def test_crypt_decrypt(self):
    #    cca = ChumCrypt(StringIO.StringIO('gubbe' * 10)


class Test_SecretBox(unittest.TestCase):

    def test_basics(self):
        box = SecretBox(key=SecretBox.new_key())
        b = box.encrypt('asd', box.new_nonce())
        print len(b), repr(b)

if __name__ == '__main__':
    unittest.main()
