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
        self.A = self.B = self.C = self.D = 0
        self.w = byte_length * 8 // 4
        self.scheduled_keys = np.zeros(2 * rounds_number + 4, dtype=type_w_dict[str(2*self.w)])
        self.key_schedule()
        self.lgw = np.uint(np.log2(self.w))

    def state_to_blocks(self):
        w_byte = self.w // 8
        self.A = self.bytearr_to_register(self.state[w_byte-1::-1])
        self.B = self.bytearr_to_register(self.state[2*w_byte-1:w_byte-1:-1])
        self.C = self.bytearr_to_register(self.state[3*w_byte-1:2*w_byte-1:-1])
        self.D = self.bytearr_to_register(self.state[4*w_byte-1:3*w_byte-1:-1])

    def bytearr_to_register(self, arr):
        reg = type_w_dict[str(2*self.w)] (0)
        for i in range(0, len(arr)):
            reg += arr[i] << np.uint(8*(len(arr)-i-1))

        return type_w_dict[str(2*self.w)](reg)

    def register_to_bytearr(self, reg, w):
        bytearr = []
        for i in range(0, w):
            bytearr.append(reg >> np.uint((8*(w-i-1))) & np.uint(0xFF))
        return bytearr

    def blocks_to_state(self):
        self.set_state(np.array([self.register_to_bytearr(elem, self.w) for elem in [self.A, self.B, self.C, self.D]]).flatten())

    def mod_mult(self, num1, num2):
        return type_w_dict[str(2*self.w)]((num1 * num2) % (2**self.w))

    def mod_add(self, num1, num2):
        return type_w_dict[str(2*self.w)]((num1 + num2) % (2 ** self.w))

    def shuffle_blocks(self):
        # (A,B,C,D) = (B,C,D,A)
        self.blocks_to_state()
        rolled_state = np.roll(self.state, -self.w)
        self.A = self.bytearr_to_register(rolled_state[0:self.w])
        self.B = self.bytearr_to_register(rolled_state[self.w:2*self.w])
        self.C = self.bytearr_to_register(rolled_state[2*self.w:3*self.w])
        self.D = self.bytearr_to_register(rolled_state[3*self.w:4*self.w])

    def get_magic_numbers(self):
        dict_key = str(self.w) + "_bit"
        return np.uint(p_w_dict[dict_key]), np.uint(q_w_dict[dict_key])

    def key_schedule(self):
        u = self.w // 8
        c = self.key_length // u or 1
        L = np.zeros(c, dtype=type_w_dict[str(2*self.w)])

        for i in range(self.key_length-1, -1, -1):
            L[i//u] = (L[i//u] << np.uint(8)) + self.key[i]

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

    def cipher(self, plain_text):
        self.set_state(plain_text)
        self.state_to_blocks()

        self.B = self.mod_add(self.B, self.scheduled_keys[0])
        self.D = self.mod_add(self.D, self.scheduled_keys[1])

        for i in range(1, self.rounds_number):
            t = self.mod_mult(self.B, self.mod_add(2*self.B, 1)) << self.lgw
            u = self.mod_mult(self.D, self.mod_add(2 * self.D, 1)) << self.lgw

            self.A = self.mod_add(((self.A ^ t) << u), self.scheduled_keys[2*i])
            self.C = self.mod_add(((self.C ^ u) << t), self.scheduled_keys[2*i+1])
            self.shuffle_blocks()

        self.A = self.mod_add(self.A, self.scheduled_keys[2 * self.rounds_number + 2])
        self.C = self.mod_add(self.C, self.scheduled_keys[2 * self.rounds_number + 3])

        print(hex(self.A))
        self.blocks_to_state()







