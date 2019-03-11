from CipherBase import CipherBase
from Aes import Aes
import numpy as np

plain_text = np.array([[0x32, 0x88, 0x31, 0xe0],
                       [0x43, 0x5a, 0x31, 0x37],
                       [0xf6, 0x30, 0x98, 0x07],
                       [0xa8, 0x8d, 0xa2, 0x34]])

key = [0x2b, 0x28, 0xab, 0x09,
       0x7e, 0xae, 0xf7, 0xcf,
       0x15, 0xd2, 0x15, 0x4f,
       0x16, 0xa6, 0x88, 0x3c]

cipherBase = CipherBase()
aes = Aes(key)
aes.set_state(plain_text^np.reshape(key, (4, 4)))

aes.sub_bytes()
aes.print_state_hex()

print("Shift")
aes.shift_rows()
aes.print_state_hex()

aes.mix_columns()
aes.print_state_hex()




