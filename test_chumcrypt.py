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
from itertools import imap
from itertools import izip
from hashlib import sha256
import random
import array

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

    def test_longer_irregular_read_lengths(self):
        key = 'a' * 32
        nonce = 'n' * 16
        cc = ChumCipher(key, nonce)
        n = 0
        while n < 2**12:
            assert len(cc._read_chum(n)) == n
            n += 31337


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

    def _inc_one_random_byte(self, s):
        a = array.array('B', s)
        i = random.randint(0, len(a) - 1)
        a[i] = (a[i] + 1) % 0xff
        return a.tostring()

    def _get_multilayer_cipher(self, keys, msg):
        '''
        Chain len(keys) ChumCiphers on top of each other.
        Return the outmost cipher object.
        '''
        n = len(keys)
        nonsense = [sha256(key).digest() for key in keys]
        ciphers = []
        i = 0
        for (key, nonce) in izip(keys, nonsense):
            if i > 0:
                msg = ciphers[i - 1]
            ciphers += [ChumCipher(key, nonce, msg)]
        return ciphers[-1]

    def test_multilayer_cipher(self):
        '''
        Create a list of keys and two equal multi-layered ciphers from these
        keys.
        Send one message through both chains and finally validate integrity.
        Perform XOR-schism...
        '''
        msg = 'Welcome! how did you get here?'
        keys = [utils.random(32) for _ in xrange(100)]
        m1 = self._get_multilayer_cipher(keys, msg)
        ciphertext = m1.read(len(msg))
        m2 = self._get_multilayer_cipher(keys, ciphertext)
        assert m2.read(len(msg)) == msg
        print(msg)

    def _recursive_boxes(self, keygen, n):
        orig_msg = 'Hello there, you again?!'
        boxes = []
        keys = [k for k in keygen]
        packages = []
        p = None
        #
        # Create n packages where package[n-1] equals the plaintext
        # of package[n].
        #
        for i in xrange(n):
            box = SecretBox(keys[i])
            if i == 0:
                msg = orig_msg
            else:
                msg = packages[i-1]
            p = box.encrypt(msg)
            packages.append(p)
        #
        # Decrypt each package p in packages. That is, n decrypt operations
        # for the first package, (n-1) for the second and so forth.
        # Assert success after each completed package series.
        #
        keys.reverse()
        packages.reverse()
        for i in xrange(len(packages)):
            p = packages[i]
            for key in keys[i:]:
                #
                # For each package, assert minor change causes HMAC validation
                # failure and thus an AssertionException.
                #
                box = SecretBox(key)
                try:
                    q = self._inc_one_random_byte(p)
                    box.decrypt(q)
                except AssertionError:
                    pass
                else:
                    raise Exception('Seal broken! more vet bills..')
                p = SecretBox(key).decrypt(p)
            assert p == orig_msg
        assert p == orig_msg
        print(p)

    def test_recursive_boxes(self):
        n = 20
        keygen = imap(lambda i: sha256(str(i)).digest(), xrange(n))
        self._recursive_boxes(keygen, n)

if __name__ == '__main__':
    unittest.main()
