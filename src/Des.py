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

        return [mat_32bits[expand_mat[i]-1] for i in range(0, 48)]

    def get_sbox_data(self, b_number, address_data):
        assert (all(i <= 1 for i in address_data))

        row = int(address_data[0] << 1 | address_data[5])
        col = int(address_data[1] << 3 | address_data[2] << 2 | address_data[3] << 1 | address_data[4])
        return sboxes[b_number][row][col]

    def des_round_function(self, data, round_key):
        data_for_sbox = self.expand_to_48bits(data) ^ round_key
        sbox_mat = [self.get_sbox_data(sbox_num, data_for_sbox[6*sbox_num:6*sbox_num+6]) for sbox_num in range(0, 8)]
        sbox_mat = np.unpackbits(np.array(sbox_mat, dtype=np.uint8))
        # sbox_mat -> 32 bits array with every 4 bits being a number from s_box
        # as sbox gives decimals there's a need to convert it to bitarray which only goes by 8 bits so the slice is made

        sbox_mat = np.array([(sbox_mat[8*i:8*i+8])[4:] for i in range(0, 8)]).flatten()
        final_perm_mat = np.array([sbox_mat[perm_mat[i]-1] for i in range(0, 32)])

        return final_perm_mat



