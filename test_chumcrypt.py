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
import os
import StringIO

from chumcrypt import ChumReader
from chumcrypt import ChumCipher
from chumcrypt import SecretBox
from chumcrypt import utils


# logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(': ***ChumReader*** :')


def debug(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.debug('  ' + msg)


def warn(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.warn('  ' + msg)


class Test_ChumReader(unittest.TestCase):

    def test_basics(self):
        key = os.urandom(32)
        nonce = os.urandom(16)
        cs = ChumReader(key=key, nonce=nonce)
        for i in xrange(100):
            assert len(cs.read_chum(i)) == i
        print(repr(cs.read_chum(29)))
        assert len(cs.read_chum(41)) == 41

    def test_longer_irregular_read_lengths(self):
        key = 'a' * 32
        nonce = 'n' * 16
        cs = ChumReader(key=key, nonce=nonce)
        n = 0
        while n < 2000:
            assert len(cs.read_chum(n)) == n
            n += 11

    def verify_param(self, name):
        pass

    def test_verify_key(self):
        pass


class Test_ChumCipher(unittest.TestCase):

    def test_basics(self):
        f = StringIO.StringIO('perkele')
        key = utils.gen_key()
        assert len(key) == 32
        nonce = os.urandom(16)
        cc = ChumCipher(f=f, key=key, nonce=nonce)
        print(repr(cc.read(29)))

    def test_longer_irregular_read_lengths(self):
        key = 'a' * 32
        nonce = 'n' * 16
        cc = ChumReader(key=key, nonce=nonce)
        n = 0
        while n < 2000:
            assert len(cc.read_chum(n)) == n
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
            plaintext = os.urandom(i)
            nonce = 'N' * 16
            package = box.encrypt(plaintext, nonce)
            assert plaintext == box.decrypt(package)

    def test_seal(self):
        key = 'K' * 32
        box = SecretBox(key)
        msg = 'hello chum'
        smsg = box.seal(msg)
        assert box.unseal(smsg) == msg


if __name__ == '__main__':
    unittest.main()
