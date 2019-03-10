from CipherBase import CipherBase
from Aes import Aes
import numpy as np


cipherBase = CipherBase()
aes = Aes()

list = [0x19, 0xa0, 0x9a, 0xe9,
        0x3d, 0xf4, 0xc6, 0xf8,
        0xe3, 0xe2, 0x8d, 0x48,
        0xbe, 0x2b, 0x2a, 0x08]

sub_byted = np.reshape([hex(x) for x in aes.sub_bytes(list)], (4, 4))


shifted = aes.shift_rows(sub_byted)
print(shifted)


aes.mix_columns(shifted.flatten())




