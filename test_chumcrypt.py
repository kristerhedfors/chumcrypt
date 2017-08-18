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
# import os

from chumcrypt import ChumCipher


# logging.basicConfig(level=logging.ERROR)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(': ***ChumCipher*** :')


def debug(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.debug('  ' + msg)


def warn(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.warn('  ' + msg)


class Test(unittest.TestCase):

    def test_basics(self):
        cs = ChumCipher()
        print(repr(cs.read(29)))
        assert len(cs.read(41)) == 41

    def test_longer_irregular_read_lengths(self):
        cs = ChumCipher()
        n = 0
        while n < 2000:
            assert len(cs.read(n)) == n
            n += 11

    def verify_param(self, name):
        pass

    def test_verify_key(self):
        pass

    def test_verify_iv(self):
        pass

    def test_verify_entropy(self):
        pass


if __name__ == '__main__':
    unittest.main()
