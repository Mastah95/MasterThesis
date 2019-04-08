from CipherBase import CipherBase
import numpy as np


class Des(CipherBase):

    def __init__(self, key, operation_mode):
        self.state = []
        self.key = key
        self.operation_mode = operation_mode
