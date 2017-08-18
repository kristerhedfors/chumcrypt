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

    def __init__(self, key='', nonce='', entropy='',
                 hashfunc=hashlib.sha256):
        # A
        if (len(nonce) + len(entropy)) < self.MIN_IV_LEN:
            err_msg = 'Not enough IV or entropy material: '
            err_msg += 'len(nonce) + len(entropy) < {0}'.format(
                self.MIN_IV_LEN)
            raise Exception(err_msg)
        # V
        self._key = key
        self._nonce = nonce
        self._entropy = entropy
        self._state = ''
        self._counter = 0
        self._buffer = ''
        # C
        pass

    def inc(self):
        ''' grow buffer with one block
        '''
        # A
        assert self._buffer == ''
        # V
        entropy = self._entropy
        block_id = struct.pack('I', self._counter)
        nonce = self._nonce
        # C
        block = hmac.new(self._key,
                         entropy + nonce + block_id).digest()
        self._buffer += block
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
                self.inc()
            res += curr
            n -= len(curr)
        return res


class ChumCrypt(ChumCipher):

    def __init__(self, f, **kw):
        # V
        self._f = f
        # C
        super(ChumCrypt, self).__init__(**kw)

    def xor(self, s1, s2):
        ''' xor two strings
        '''
        # A
        assert len(s1) == len(s2)
        # C
        x = [chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2)]
        return ''.join(x)

    def read(self, n):
        ''' read and xor n bytes from fa and fb
        '''
        # V
        buf = self._f.read(n)
        chum = self.read_chum(len(buf))
        # C
        return self.xor(buf, chum)


class SecretBox(object):

    NONCE_LEN = 16

    def __init__(self, key, nonce=None, cipher_cls=ChumCipher):
        # A
        if nonce is None:
            nonce = os.urandom(self.NONCE_LEN)
        elif len(nonce) != self.NONCE_LEN:
            msg = 'Invalid nonce length, len(nonce) != ' + str(self.NONCE_LEN)
            raise Exception(msg)
        # V
        self._cipher = cipher_cls(key=key, nonce=nonce)
        # C
        self._cipher = cipher
        self._f = f


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
