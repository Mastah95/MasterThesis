from CipherBase import CipherBase
from DesConstants import ip, ip_inv, expand_mat, sboxes, perm_mat, key_perm_1, key_perm_2
import numpy as np


class Des(CipherBase):

    def __init__(self, key, operation_mode):
        self.state = []
        self.key = key
        self.operation_mode = operation_mode

    def get_left_part(self):
        return self.state[:len(self.state)//2]

    def get_right_part(self):
        return self.state[len(self.state)//2:]

    def expand_to_48bits(self, mat_32bits):
        assert(all(i <= 1 for i in mat_32bits))

        return [mat_32bits[expand_mat[i]] for i in range(0, 48)]

    def get_sbox_data(self, b_number, address_data):
        assert (all(i <= 1 for i in address_data))

        row = int(address_data[0] << 1 | address_data[5])
        col = int(address_data[1] << 3 | address_data[2] << 2 | address_data[3] << 1 | address_data[4])
        return sboxes[b_number][row][col]

