
from CipherBase import CipherBase
from AesConstants import aes_sbox, aes_sbox_inv, aes_rcon, mix_col_mult
import numpy as np


class Aes(CipherBase):

    def __init__(self):
        self.key = b'\xFF\xFF\xFF\xFF'
        self.sbox = aes_sbox
        self.sbox_inv = aes_sbox_inv
        self.rcon = aes_rcon

    def sub_bytes(self, block):
        return [aes_sbox[elem] for elem in block]

    def shift_rows(self, block):
        shifted = []
        for i, column in enumerate(block):
            shifted.append(np.roll(column, -i))
        return np.asarray(shifted)

    def galois_field_mult(self, a, b):
        p = 0
        for i in range(0, 8):
            if b & 1:
                p ^= a
            if a & 0x80:
                a = (a << 1) ^ 0x11b
            else:
                a <<= 1
            b >>= 1
        return p

    def mix_columns(self, block):
        for i in range(0, 4):
            col = block[i:i+16:4]
            col = [int(elem, 0) for elem in col]
            col_cpy = col.copy()
            gfm = self.galois_field_mult  # alias for method
            col[0] = gfm(col_cpy[0], mix_col_mult[0]) ^ gfm(col_cpy[3], mix_col_mult[1]) ^ \
                     gfm(col_cpy[2], mix_col_mult[2]) ^ gfm(col_cpy[1], mix_col_mult[3])

            col[1] = gfm(col_cpy[1], mix_col_mult[0]) ^ gfm(col_cpy[0], mix_col_mult[1]) ^ \
                     gfm(col_cpy[3], mix_col_mult[2]) ^ gfm(col_cpy[2], mix_col_mult[3])

            col[2] = gfm(col_cpy[2], mix_col_mult[0]) ^ gfm(col_cpy[1], mix_col_mult[1]) ^ \
                     gfm(col_cpy[0], mix_col_mult[2]) ^ gfm(col_cpy[3], mix_col_mult[3])

            col[3] = gfm(col_cpy[3], mix_col_mult[0]) ^ gfm(col_cpy[2], mix_col_mult[1]) ^ \
                     gfm(col_cpy[1], mix_col_mult[2]) ^ gfm(col_cpy[0], mix_col_mult[3])

            block[i:i + 16:4] = [hex(x) for x in col]
        print(np.reshape(block, (4, 4)))

    def add_round_key(self, block):
        pass

    def round(self, block, isLast):
        self.sub_bytes(block)
        self.shift_rows(block)
        if not isLast:
            self.mix_columns(block)
        self.add_round_key(block)
