from CipherBase import CipherBase
from DesConstants import ip, ip_inv, expand_mat, sboxes, perm_mat, key_perm_1, key_perm_2
import numpy as np


class Des(CipherBase):

    def __init__(self, key, operation_mode):
        self.state = []
        self.set_key_from_bytes(key)
        self.check_key()
        self.operation_mode = operation_mode
        self.scheduled_keys = []
        self.schedule_keys()

    def check_key(self):
        for i in range(0, 8):
            byte = self.key[i*8:i*8+8]
            if not np.count_nonzero(byte) % 2:
                raise KeyError('Des key not paired properly')

    def schedule_keys(self):
        base_key = np.array([self.key[key_perm_1[i]-1] for i in range(0, 56)])
        for i in range(1, 17):
            left_part = self.get_left_part(base_key)
            right_part = self.get_right_part(base_key)
            base_key = np.concatenate((self.roll_key(left_part, i), self.roll_key(right_part, i)))
            scheduled_key = np.array([base_key[key_perm_2[i]-1] for i in range(0, 48)])
            self.scheduled_keys.append(scheduled_key)

    def roll_key(self, key_part, number):
        roll_number = 1 if number in [1, 2, 9, 16] else 2
        return np.roll(key_part, -roll_number)

    def drop_every_eighth_element(self, arr):
        return np.array([elem[1] for elem in enumerate(arr) if (elem[0]+1) % 8])

    def strip_beginning_4_zeros(self, data_8bit):
        return data_8bit[4:]

    def byte_to_4bits(self, byte):
        return self.strip_beginning_4_zeros(np.unpackbits(np.array(byte, dtype=np.uint8)))

    def set_state_from_bytes(self, byte_arr):
        assert(len(byte_arr) == 16)
        self.state = np.array([self.byte_to_4bits(byte) for byte in byte_arr]).flatten()

    def set_key_from_bytes(self, byte_key):
        assert (len(byte_key) == 16)
        self.key = np.array([self.byte_to_4bits(byte) for byte in byte_key]).flatten()

    def get_left_part(self, arr):
        return arr[:len(arr)//2]

    def get_right_part(self, arr):
        return arr[len(arr)//2:]

    def initial_permutation(self):
        self.set_state(np.array([self.state[ip[i]-1] for i in range(0, 64)]))

    def expand_to_48bits(self, mat_32bits):
        assert(all(i <= 1 for i in mat_32bits))

        return np.array([mat_32bits[expand_mat[i]-1] for i in range(0, 48)]).flatten()

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

        sbox_mat = np.array([self.strip_beginning_4_zeros(sbox_mat[8*i:8*i+8]) for i in range(0, 8)]).flatten()
        final_perm_mat = np.array([sbox_mat[perm_mat[i]-1] for i in range(0, 32)])

        return final_perm_mat

    def round(self, round_number):
        li = self.get_left_part(self.state)
        ri = self.get_right_part(self.state)
        new_ri = li ^ self.des_round_function(ri, self.scheduled_keys[round_number])
        print(f'RRR{new_ri}, {type(new_ri)}')
        self.set_state(np.concatenate((ri, new_ri)))

    def cipher(self, plain_text):
        self.set_state_from_bytes(plain_text)
        self.initial_permutation()

        for i in range(0, 16):
            self.round(i)

        self.set_state(np.concatenate((self.get_right_part(self.state), self.get_left_part(self.state))))
        self.set_state(np.array([self.state[ip_inv[i]-1] for i in range(0, 64)]))


