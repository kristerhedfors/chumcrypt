#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
#
#
import unittest
import sys
import logging
import hashlib
import hmac
import struct
import os


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def debug(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.debug('  ' + msg)


def main(*args):
    pass


def Entropy(object):
    'shuffle and read data from proc'
    pass


class ChumStream(object):

    def __init__(self, key='', iv='', entropy='', hashfunc=hashlib.sha256):
        self._key = key
        self._iv = iv
        self._state = ''
        self._counter = 0
        self._buffer = ''
        if not entropy:
            entropy = os.urandom(32)
        self._entropy = entropy

    def inc(self):
        'grow buffer with one block'
        assert self._buffer == ''
        #
        entropy = self._entropy
        block_id = struct.pack('I', self._counter)
        iv = self._iv
        #
        block = hmac.new(self._key,
                         entropy + iv + block_id).digest()
        self._buffer += block
        self._counter += 1

    def read(self, n):
        'return n bytes from buffer'
        res = ''
        while n > 0:
            batch_size = min(n, 16)
            curr, self._buffer = self._buffer[:batch_size], \
                                 self._buffer[batch_size:]
            if self._buffer == '' or len(curr) < batch_size:
                self.inc()
            res += curr
            n -= len(curr)
        return res


class Test(unittest.TestCase):

    def test_basics(self):
        cs = ChumStream()
        print(repr(cs.read(29)))
        assert len(cs.read(41)) == 41

    def test_longer_irregular_reads(self):
        cs = ChumStream()
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
    sys.exit()
    ##########
    if '--test' in sys.argv:
        sys.argv.remove('--test')
        unittest.main()
    else:
        sys.exit(main(*sys.argv[1:]))

