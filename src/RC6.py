from CipherBase import CipherBase
from RC6Constants import p_w_dict, q_w_dict, type_w_dict
import numpy as np


class RC6(CipherBase):

    def __init__(self, key, operation_mode, byte_length, rounds_number):
        CipherBase.__init__(self, operation_mode, byte_length)
        self.state = []
        self.key = key
        self.rounds_number = rounds_number
        self.key_length = len(key)
        self.A = self.B = self.C = self.D = []
        self.w = byte_length * 8 // 4
        self.scheduled_keys = np.zeros(2 * rounds_number + 4, dtype=type_w_dict[str(4*self.w)])
        #self.key_schedule()

    def state_to_blocks(self):
        self.A = self.state[self.w-1::-1]
        self.B = self.state[2*self.w-1:self.w-1:-1]
        self.C = self.state[3*self.w-1:2*self.w-1:-1]
        self.D = self.state[4*self.w-1:3*self.w-1:-1]

    def blocks_to_state(self):
        self.set_state(np.array([self.A, self.B, self.C, self.D]).flatten())

    def mod_mult(self, num1, num2):
        return type_w_dict[str(2*self.w)]((num1 * num2) % 2**self.w)

    def mod_add(self, num1, num2):
        return type_w_dict[str(2*self.w)]((num1 + num2) % 2 ** self.w)

    def get_magic_numbers(self):
        dict_key = str(self.w) + "_bit"
        return np.uint(p_w_dict[dict_key]), np.uint(q_w_dict[dict_key])

    def key_schedule(self):
        u = self.w // 8
        c = self.key_length // u or 1
        L = np.zeros(c, dtype=type_w_dict[str(2*self.w)])

        for i in range(self.key_length-1, -1, -1):
            L[i//u] = (L[i//u] << np.uint(8)) + self.key[i]

        print([hex(elem) for elem in L])
        p_w, q_w = self.get_magic_numbers()
        self.scheduled_keys[0] = p_w

        for i in range(1, self.rounds_number+3):
            self.scheduled_keys[i] = self.mod_add(self.scheduled_keys[i-1], q_w)

        v = self.mod_mult(3, max(c, 2*self.rounds_number+4))
        A = B = i = j = type_w_dict[str(2*self.w)](0)
        for s in range(1, v):
            A = self.scheduled_keys[i] = self.mod_add(self.scheduled_keys[i], self.mod_add(A, B)) << np.uint(3)
            B = L[j] = self.mod_add(L[j], self.mod_add(A, B)) << self.mod_add(A, B)
            i = int((i + 1) % (2 * self.rounds_number + 4))
            j = int((j + 1) % c)

        print(self.scheduled_keys[0])







