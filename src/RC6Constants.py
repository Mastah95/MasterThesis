import numpy as np

#magic numbers

p_w_dict = {
    "16_bit":   0xb7e1,
    "32_bit":   0xb7e15163,
    "64_bit":   0xb7e151628aed2a6d
}

q_w_dict = {
    "16_bit": 0x9e37,
    "32_bit": 0x9e3779b9,
    "64_bit": 0x9e3779b97f4a7c15
}

type_w_dict = {
    "8": np.uint8,
    "16": np.uint16,
    "32": np.uint32,
    "64": np.uint64
}
