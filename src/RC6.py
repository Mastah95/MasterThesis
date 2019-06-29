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
        self.lgw = np.uint(np.log2(self.w))
        self.scheduled_keys = np.zeros(2 * rounds_number + 4, dtype=type_w_dict[str(self.w)])
        self.schedule_keys()

    def rotr(self, x, n, num_bytes=np.uint(32)):
        n = n << np.uint(self.w - self.lgw)
        n = n >> np.uint(self.w - self.lgw)
        x = type_w_dict[str(self.w)](x)
        return (x >> n) | (x << (num_bytes - n))

    def rotl(self, x, n, num_bytes=np.uint(32)):

        n = n << np.uint(self.w - self.lgw)
        n = n >> np.uint(self.w - self.lgw)
        x = type_w_dict[str(self.w)](x)
        return (x << n) | (x >> (num_bytes - n))

    def state_to_blocks(self):
        w_byte = self.w // 8
        self.A = self.bytearr_to_register(self.state[w_byte-1::-1])
        self.B = self.bytearr_to_register(self.state[2*w_byte-1:w_byte-1:-1])
        self.C = self.bytearr_to_register(self.state[3*w_byte-1:2*w_byte-1:-1])
        self.D = self.bytearr_to_register(self.state[4*w_byte-1:3*w_byte-1:-1])

    def bytearr_to_register(self, arr):
        reg = type_w_dict[str(self.w)] (0)
        for i in range(0, len(arr)):
            reg += arr[i] << np.uint(8*(len(arr)-i-1))

        return type_w_dict[str(self.w)](reg)

    def register_to_bytearr(self, reg, w):
        bytearr = []
        for i in range(0, w//8):
            bytearr.append(reg >> np.uint((8*(w-i-1))) & np.uint(0xFF))

        return bytearr

    def register_to_bytearr_endian(self, reg, w):
        bytearr = []
        for i in range(0, w//8):
            bytearr.append(reg >> np.uint((8*i)) & np.uint(0xFF))

        return bytearr


    def blocks_to_state(self):
        self.set_state(np.array([self.register_to_bytearr(elem, self.w) for elem in [self.A, self.B, self.C, self.D]]).flatten())

    def blocks_to_state_endian(self):
        self.set_state(np.array([self.register_to_bytearr_endian(elem, self.w) for elem in [self.A, self.B, self.C, self.D]]).flatten())

    def mod_mult(self, num1, num2):

        num = (int(num1) * int(num2)) % (2**self.w)
        return type_w_dict[str(self.w)](num)

    def mod_add(self, num1, num2):
        return type_w_dict[str(self.w)]((int(num1) + int(num2)) % (2 ** self.w))

    def left_shuffle_blocks(self):
        # (A,B,C,D) = (B,C,D,A)
        w_byte = self.w // 8
        self.blocks_to_state()
        rolled_state = np.roll(self.state, -w_byte)
        self.A = self.bytearr_to_register(rolled_state[0:w_byte])
        self.B = self.bytearr_to_register(rolled_state[w_byte:2*w_byte])
        self.C = self.bytearr_to_register(rolled_state[2*w_byte:3*w_byte])
        self.D = self.bytearr_to_register(rolled_state[3*w_byte:4*w_byte])


    def right_shuffle_blocks(self):
        # (A,B,C,D) = (B,C,D,A)
        w_byte = self.w // 8

        self.blocks_to_state()
        rolled_state = np.roll(self.state, w_byte)
        self.A = self.bytearr_to_register(rolled_state[0:w_byte])
        self.B = self.bytearr_to_register(rolled_state[w_byte:2 * w_byte])
        self.C = self.bytearr_to_register(rolled_state[2 * w_byte:3 * w_byte])
        self.D = self.bytearr_to_register(rolled_state[3 * w_byte:4 * w_byte])


    def get_magic_numbers(self):
        dict_key = str(self.w) + "_bit"
        return np.uint(p_w_dict[dict_key]), np.uint(q_w_dict[dict_key])

    def schedule_keys(self):
        u = self.w // 8
        c = self.key_length // u or 1
        L = np.zeros(c, dtype=type_w_dict[str(self.w)])

        for i in range(self.key_length-1, -1, -1):
            L[i//u] = (L[i//u] << np.uint(8)) + self.key[i]

        p_w, q_w = self.get_magic_numbers()

        self.scheduled_keys[0] = p_w

        for i in range(1, 2*self.rounds_number+4):
            self.scheduled_keys[i] = self.mod_add(self.scheduled_keys[i-1], q_w)

        v = 3 * max(c, (2*self.rounds_number+4))
        A = B = i = j = type_w_dict[str(self.w)](0)
        for s in range(1, v+1):
            A = self.scheduled_keys[i] = self.rotl(self.mod_add(self.scheduled_keys[i], self.mod_add(A, B)), np.uint(3))
            B = L[j] = self.rotl(self.mod_add(L[j], self.mod_add(A, B)), self.mod_add(A, B))
            i = int((i + 1) % (2 * self.rounds_number + 4))
            j = int((j + 1) % c)

    def cipher(self, plain_text):
        self.set_state(plain_text)
        self.state_to_blocks()

        self.B = self.mod_add(self.B, self.scheduled_keys[0])
        self.D = self.mod_add(self.D, self.scheduled_keys[1])

        for i in range(1, self.rounds_number+1):
            t = self.rotl(self.mod_mult(self.B, self.mod_add(2*self.B, 1)), self.lgw)
            u = self.rotl(self.mod_mult(self.D, self.mod_add(2 * self.D, 1)), self.lgw)

            self.A = self.mod_add(self.rotl((self.A ^ t), u), self.scheduled_keys[2*i])

            self.C = self.mod_add(self.rotl((self.C ^ u), t), self.scheduled_keys[2*i+1])

            self.left_shuffle_blocks()

        self.A = self.mod_add(self.A, self.scheduled_keys[2 * self.rounds_number + 2])
        self.C = self.mod_add(self.C, self.scheduled_keys[2 * self.rounds_number + 3])

        self.blocks_to_state_endian()

    def decipher(self, cipher_text):
        self.set_state(cipher_text)
        self.state_to_blocks()

        self.C = self.mod_add(self.C, -self.scheduled_keys[2 * self.rounds_number + 3])
        self.A = self.mod_add(self.A, -self.scheduled_keys[2 * self.rounds_number + 2])

        for i in range(self.rounds_number, 0, -1):
            self.right_shuffle_blocks()
            t = self.rotl(self.mod_mult(self.B, self.mod_add(2 * self.B, 1)), self.lgw)
            u = self.rotl(self.mod_mult(self.D, self.mod_add(2 * self.D, 1)), self.lgw)

            self.C = self.rotr(self.mod_add(self.C, -self.scheduled_keys[2*i + 1]), t) ^ u
            self.A = self.rotr(self.mod_add(self.A, -self.scheduled_keys[2*i]), u) ^ t

        self.D = self.mod_add(self.D, -self.scheduled_keys[1])
        self.B = self.mod_add(self.B, -self.scheduled_keys[0])

        self.blocks_to_state_endian()







