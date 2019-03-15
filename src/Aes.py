
from CipherBase import CipherBase
from AesConstants import aes_sbox, aes_sbox_inv, aes_rcon, mix_col_mult, mix_col_mult_inv
import numpy as np


class Aes(CipherBase):

    def __init__(self, key):
        self.key = key
        self.sbox = aes_sbox
        self.sbox_inv = aes_sbox_inv
        self.rcon = aes_rcon
        self.chunk_size = 65536  # 64 KB
        self.state = []
        self.key_schedule = [self.key]
        self.schedule_key(10)
    
    def set_state(self, block):
        self.state = block

    @staticmethod
    def print_mat_hex(matrix):
        print(np.reshape([hex(x) for x in matrix.flatten()], (4, 4)))

    def print_state_hex(self):
        self.print_mat_hex(self.state)

    def sub_bytes(self):
        self.state = np.reshape([aes_sbox[elem] for elem in self.state.flatten()], (4, 4))

    def sub_bytes_inv(self):
        self.state = np.reshape([aes_sbox_inv[elem] for elem in self.state.flatten()], (4, 4))

    def shift_rows(self):
        shifted = []
        for i, column in enumerate(self.state):
            shifted.append(np.roll(column, -i))
        self.state = np.asarray(shifted)

    def shift_rows_inv(self):
        shifted = []
        for i, column in enumerate(self.state):
            shifted.append(np.roll(column, i))
        self.state = np.asarray(shifted)

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

    def mix_columns(self, isInv):
        block = self.state.flatten()

        if not isInv:
            mult = mix_col_mult
        else:
            mult = mix_col_mult_inv

        for i in range(0, 4):
            col = block[i:i+16:4]
            col_cpy = col.copy()
            gfm = self.galois_field_mult  # alias for method

            col[0] = gfm(col_cpy[0], mult[0]) ^ gfm(col_cpy[3], mult[1]) ^ \
                     gfm(col_cpy[2], mult[2]) ^ gfm(col_cpy[1], mult[3])

            col[1] = gfm(col_cpy[1], mult[0]) ^ gfm(col_cpy[0], mult[1]) ^ \
                     gfm(col_cpy[3], mult[2]) ^ gfm(col_cpy[2], mult[3])

            col[2] = gfm(col_cpy[2], mult[0]) ^ gfm(col_cpy[1], mult[1]) ^ \
                     gfm(col_cpy[0], mult[2]) ^ gfm(col_cpy[3], mult[3])

            col[3] = gfm(col_cpy[3], mult[0]) ^ gfm(col_cpy[2], mult[1]) ^ \
                     gfm(col_cpy[1], mult[2]) ^ gfm(col_cpy[0], mult[3])

            block[i:i + 16:4] = col

        self.state = np.reshape(block, (4, 4))

    def schedule_key(self, number_of_rounds):
        counter = 0
        for key in self.key_schedule or counter == number_of_rounds:
            if counter == number_of_rounds:
                break

            key_cp = key
            for i in range(0, 4):
                if not i:
                    word = np.array([aes_sbox[elem] for elem in np.roll(key_cp[:, 3], -1)]) ^ np.array([aes_rcon[counter], 0, 0, 0]) \
                           ^ key_cp[:, 0]
                else:
                    word = key_cp[:, 0+i] ^ key_cp[:, 3+i]
                key_cp = np.column_stack((key_cp, word))

            counter += 1
            self.key_schedule.append(key_cp[:, 4:8])

    def add_round_key(self, round_key):
        self.state ^= round_key

    def round(self, isLast, round_number):
        self.sub_bytes()
        self.shift_rows()
        if not isLast:
            self.mix_columns(isInv=False)
        self.add_round_key(self.key_schedule[round_number+1])

    def cipher(self, plain_text, key):
        self.set_state(plain_text ^ key)
        for i in range(0, 10):
            self.round(i == 9, i)

    def round_inv(self, isFirst, round_number):
        self.add_round_key(self.key_schedule[-1-round_number])
        if not isFirst:
            self.mix_columns(isInv=True)
        self.shift_rows_inv()
        self.sub_bytes_inv()

    def decipher(self, crypt_text, key):
        self.set_state(crypt_text)
        for i in range(0, 10):
            self.round_inv(i == 0, i)
        self.set_state(self.state ^ key)

