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
        cc = ChumCipher(f=f, key=key, nonce=nonce)
        print(repr(cc.read(29)))

    def test_longer_irregular_read_lengths(self):
        key = 'a' * 32
        nonce = 'n' * 16
        cc = ChumCipher(f=None, key=key, nonce=nonce)
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


if __name__ == '__main__':
    unittest.main()
