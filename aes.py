
''' AES – Implements the Advanced Encryption Standard '''
#
# Copyright 2008 Josh Davis <http://www.josh-davis.org>
# Copyright 2008 Alex Martelli <http://www.aleax.it>
# Copyright 2011 Stefano Palazzo <http://plzz.de/>
#
# Modified version of the SlowAES project <http://code.google.com/p/slowaes/>,
# Ported from C code by Laurent Haan <http://www.progressive-coding.com>.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import os
import hashlib
import hmac
import pickle
import base64
import random


class AES(object):

    sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

    def get_sbox_value(self, num):
        return self.sbox[num]

    def get_sbox_invert(self, num):
        return self.rsbox[num]

    def rotate(self, word):
        return word[1:] + word[:1]

    rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
            0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
            0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
            0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
            0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
            0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
            0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
            0xe8, 0xcb]

    def get_rcon_value(self, num):
        return self.rcon[num]

    def core(self, word, iteration):
        word = self.rotate(word)
        for i in range(4):
            word[i] = self.get_sbox_value(word[i])
        word[0] = word[0] ^ self.get_rcon_value(iteration)
        return word

    def expand_key(self, key, size, expanded_key_size):
        current_size = 0
        rcon_iteration = 1
        expanded_key = [0] * expanded_key_size
        for j in range(size):
            expanded_key[j] = key[j]
        current_size += size
        while current_size < expanded_key_size:
            t = expanded_key[current_size - 4:current_size]
            if current_size % size == 0:
                t = self.core(t, rcon_iteration)
                rcon_iteration += 1
            if size == 32 and ((current_size % size) == 16):
                for l in range(4):
                    t[l] = self.get_sbox_value(t[l])
            for m in range(4):
                expanded_key[current_size] = (
                    expanded_key[current_size - size] ^ t[m])
                current_size += 1
        return expanded_key

    def add_round_key(self, state, round_key):
        for i in range(16):
            state[i] ^= round_key[i]
        return state

    def create_round_key(self, expanded_key, round_key_pointer):
        round_key = [0] * 16
        for i in range(4):
            for j in range(4):
                round_key[j * 4 + i] = expanded_key[
                    round_key_pointer + i * 4 + j]
        return round_key

    def galois_multiplication(self, a, b):
        p = 0
        for counter in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    def sub_bytes(self, state, is_inv):
        if is_inv:
            getter = self.get_sbox_invert
        else:
            getter = self.get_sbox_value
        for i in range(16):
            state[i] = getter(state[i])
        return state

    def shift_rows(self, state, is_inv):
        for i in range(4):
            state = self.shift_row(state, i * 4, i, is_inv)
        return state

    def shift_row(self, state, state_pointer, nbr, is_inv):
        for i in range(nbr):
            if is_inv:
                state[state_pointer:state_pointer + 4] = (
                    state[state_pointer + 3:state_pointer + 4] +
                    state[state_pointer:state_pointer + 3])
            else:
                state[state_pointer:state_pointer + 4] = (
                    state[state_pointer + 1:state_pointer + 4] +
                    state[state_pointer:state_pointer + 1])
        return state

    def mix_columns(self, state, is_inv):
        for i in range(4):
            column = state[i:i + 16:4]
            column = self.mix_column(column, is_inv)
            state[i:i + 16:4] = column
        return state

    def mix_column(self, column, is_inv):
        if is_inv:
            mult = [14, 9, 13, 11]
        else:
            mult = [2, 1, 1, 3]
        cpy = list(column)
        g = self.galois_multiplication
        column[0] = (g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^
            g(cpy[2], mult[2]) ^ g(cpy[1], mult[3]))
        column[1] = (g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^
            g(cpy[3], mult[2]) ^ g(cpy[2], mult[3]))
        column[2] = (g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^
            g(cpy[0], mult[2]) ^ g(cpy[3], mult[3]))
        column[3] = (g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^
            g(cpy[1], mult[2]) ^ g(cpy[0], mult[3]))
        return column

    def aes_round(self, state, round_key):
        state = self.sub_bytes(state, False)
        state = self.shift_rows(state, False)
        state = self.mix_columns(state, False)
        state = self.add_round_key(state, round_key)
        return state

    def aes_inv_round(self, state, round_key):
        state = self.shift_rows(state, True)
        state = self.sub_bytes(state, True)
        state = self.add_round_key(state, round_key)
        state = self.mix_columns(state, True)
        return state

    def aes_main(self, state, expanded_key, n_rounds):
        state = self.add_round_key(state,
            self.create_round_key(expanded_key, 0))
        i = 1
        while i < n_rounds:
            state = self.aes_round(state,
                self.create_round_key(expanded_key, 16 * i))
            i += 1
        state = self.sub_bytes(state, False)
        state = self.shift_rows(state, False)
        state = self.add_round_key(state,
            self.create_round_key(expanded_key, 16 * n_rounds))
        return state

    def aes_inv_main(self, state, expanded_key, n_rounds):
        state = self.add_round_key(state,
            self.create_round_key(expanded_key, 16 * n_rounds))
        i = n_rounds - 1
        while i > 0:
            state = self.aes_inv_round(state,
                self.create_round_key(expanded_key, 16 * i))
            i -= 1
        state = self.shift_rows(state, True)
        state = self.sub_bytes(state, True)
        state = self.add_round_key(state,
            self.create_round_key(expanded_key, 0))
        return state

    def encrypt(self, data, key):
        result = bytearray(16)
        block = bytearray(16)
        if len(key) == 16:
            n_rounds = 10
        elif len(key) == 24:
            n_rounds = 12
        elif len(key) == 32:
            n_rounds = 14
        else:
            raise ValueError("key must be 16, 24 or 32 bytes long")
        expanded_key_size = 16 * (n_rounds + 1)
        for i in range(4):
            for j in range(4):
                block[(i + (j * 4))] = data[(i * 4) + j]
        expanded_key = self.expand_key(key, len(key), expanded_key_size)
        block = self.aes_main(block, expanded_key, n_rounds)
        for k in range(4):
            for l in range(4):
                result[(k * 4) + l] = block[(k + (l * 4))]
        return bytes(result)

    def decrypt(self, data, key):
        result = bytearray(16)
        block = bytearray(16)
        if len(key) == 16:
            n_rounds = 10
        elif len(key) == 24:
            n_rounds = 12
        elif len(key) == 32:
            n_rounds = 14
        else:
            raise ValueError("key must be 16, 24 or 32 bytes long")
        expanded_key_size = 16 * (n_rounds + 1)
        for i in range(4):
            for j in range(4):
                block[(i + (j * 4))] = data[(i * 4) + j]
        expanded_key = self.expand_key(key, len(key), expanded_key_size)
        block = self.aes_inv_main(block, expanded_key, n_rounds)
        for k in range(4):
            for l in range(4):
                result[(k * 4) + l] = block[(k + (l * 4))]
        return bytes(result)


class AESModeOfOperationCBC (object):

    def __init__(self, iv):
        if len(iv) != 16:
            raise ValueError("iv must be 16 bytes long")
        self.aes = AES()
        self.iv = iv

    @staticmethod
    def pad(data):
        padding_length = 16 - (len(data) % 16)
        return data + bytes(padding_length for i in range(padding_length))

    @staticmethod
    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    @staticmethod
    def check_padding(data):
        if not data or len(data) % 16:
            raise ValueError("padding error")
        if data[-1] > 16:
            raise ValueError("padding error")
        if not all(i == data[-1] for i in data[-data[-1]:]):
            raise ValueError("padding error")

    @staticmethod
    def xor(a, b):
        return bytes(i ^ j for i, j in zip(a, b))

    def encrypt(self, data, key):
        data, p, result = self.pad(data), self.iv, b''
        for i in range(len(data) // 16):
            plain = data[i * 16:i * 16 + 16]
            ciph = self.aes.encrypt(self.xor(plain, p), key)
            result, p = result + ciph, ciph
        return result

    def decrypt(self, data, key):
        result, p = b'', self.iv
        for i in range(len(data) // 16):
            ciph = data[i * 16:i * 16 + 16]
            plain = self.xor(self.aes.decrypt(ciph, key), p)
            p = ciph
            result += plain
        self.check_padding(result)
        return self.unpad(result)


def cbc_encrypt(data, key, iv):
    mo = AESModeOfOperationCBC(iv)
    return mo.encrypt(data, key)


def cbc_decrypt(data, key, iv):
    mo = AESModeOfOperationCBC(iv)
    return mo.decrypt(data, key)


def stretch(passphrase, iterations, salt):
    passphrase = passphrase.encode()
    key = hashlib.sha256(passphrase + salt)
    for i in range(iterations):
        key = hashlib.sha256(key.digest() + passphrase + salt)
    return key.digest()


def wrap(text, length):
    x = len(text) // length + (1 if len(text) % length else 0)
    return '\n'.join(text[i * length:i * length + length]
        for i in range(x))


def encrypt(data, passphrase, iterations=8192, salt_length=32):
    '''
        Encrypt data using AES256-CBC

        This function encrypts the data (bytes) using
        a streteched version of the passphrase (sha256)
        with a sha256 hmac for authentication. And returns
        a urlsafe base64 encoded string containing the
        pickled components of the secret.

        The passphrase is a string of arbitrary length.
        The iterations and salt_length arguments have
        an impact on the speed of the key generating
        function. They should be as high as possible.
        A random number (0-128) of random bytes is added
        to the plain text to further obfuscate its length.
        When decrypting, The plain text is also checked
        for integrity using its sha256 checksum.

    '''
    rand = os.urandom(random.randint(0, 128))
    data = pickle.dumps((data, rand))
    h = hashlib.sha256(data).hexdigest()
    salt, iv = os.urandom(salt_length), os.urandom(16)
    key = stretch(passphrase, iterations, salt)
    ciphertext = cbc_encrypt(data, key, iv)
    data = pickle.dumps((ciphertext, salt, iterations, iv))
    mac = hmac.new(key, data, hashlib.sha256).digest()
    data = pickle.dumps((data, mac, h))
    ciph = base64.b64encode(data).decode()
    return wrap(ciph, 64)


def decrypt(data, passphrase):
    try:
        data = data.replace(" ", "").replace("\n", "")
        data = data.replace("\t", "").replace("\r", "")
        data = base64.b64decode(data.encode(), validate=True)
        data, mac, h = pickle.loads(data)
        ciphertext, salt, iterations, iv = pickle.loads(data)
        key = stretch(passphrase, iterations, salt)
        assert mac == hmac.new(key, data, hashlib.sha256).digest()
        plain_text = cbc_decrypt(ciphertext, key, iv)
        assert h == hashlib.sha256(plain_text).hexdigest()
        data, rand = pickle.loads(plain_text)
        return data
    except Exception as e:
        print(e)
    raise ValueError("decryption error")


__all__ = ("encrypt", "decrypt")
