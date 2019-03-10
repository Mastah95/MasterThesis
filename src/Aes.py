from CipherBase import CipherBase
from AesConstants import aes_sbox, aes_sbox_inv, aes_rcon, mix_col_mat
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

    def mix_columns(self, block):
        col_block = []
        for i in range(0, 4):
            col = block[i:i+16:4]
            col = [int(elem, 0) for elem in col]
            print(np.matmul(mix_col_mat, np.transpose(col)))

    def add_round_key(self, block):
        pass

    def round(self, block, isLast):
        self.sub_bytes(block)
        self.shift_rows(block)
        if not isLast:
            self.mix_columns(block)
        self.add_round_key(block)
