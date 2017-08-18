#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2017 - Krister Hedfors
#
#
import sys
import logging
import hashlib
import hmac
import struct
import os

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

    MIN_IV_LEN = 16

    def __init__(self, key='', iv='', entropy='', hashfunc=hashlib.sha256):
        if (len(iv) + len(entropy)) < self.MIN_IV_LEN:
            err_msg = 'Not enough IV or entropy material: '
            err_msg += 'len(iv) + len(entropy) < {0}'.format(self.MIN_IV_LEN)
            raise Exception(err_msg)
        ##
        self._key = key
        self._iv = iv
        self._entropy = entropy
        self._state = ''
        self._counter = 0
        self._buffer = ''
        ##
        pass

    def inc(self):
        ''' grow buffer with one block
        '''
        assert self._buffer == ''
        ##
        entropy = self._entropy
        block_id = struct.pack('I', self._counter)
        iv = self._iv
        ##
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


class ChumXOR(object):

    def __init__(self, cipher, f):
        'read and xor data from file-like objects (fa, fb)'
        self._cipher = cipher
        self._f = f

    def xor(self, s1, s2):
        'xor two strings'
        assert len(s1) == len(s2)
        #
        x = [chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2)]
        return ''.join(x)

    def read(self, n):
        'read and xor n bytes from fa and fb'
        # broken
        buf = self._f.read(n)
        chum = self._cipher.read(n)
        return self.xor(buf, chum)


class ChumReader(ChumXOR):

    def __init__(self, cipher=None, f=None):
        self._cipher = cipher
        self._f = f


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
