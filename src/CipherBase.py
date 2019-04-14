import numpy as np


class CipherBase:

    def __init__(self, operation_mode):
        self.state = np.array(np.zeros((4, 4)))
        self.mode = operation_mode
        self.iv = np.array(np.ones((4, 4)), dtype=int)
        self.xor_factor = self.iv

    def set_state(self, block):
        self.state = block

    def cipher(self):
        pass

    def decipher(self):
        pass

    def round(self):
        pass

    def append_PKCS7_padding(self, data):
        pad = 16 - (len(data) % 16)
        byt = bytes([ord(c) for c in (chr(pad) * pad)])
        return data + byt

    def remove_PKCS7_padding(self, data):
        if len(data) % 16 != 0:
            raise ValueError("Data not padded properly")

        pad = ord(data[-1])

        if pad > 16:
            raise ValueError("Ascii value more than possible padding")

        return data[:-pad]

    def cipher_text_file(self, filename, key):
        padded = False

        with open(filename, "rb") as in_file, open('cipher.txt', 'wb') as out_file:
            while True:
                piece = in_file.read(self.chunk_size)
                if piece == b'':
                    break  # end of file
                cipher = bytearray()

                if len(piece) % 16 != 0 or (in_file.peek(self.chunk_size) == 'b' and not padded):
                    piece = self.append_PKCS7_padding(piece)
                    padded = True

                for i in range(0, len(piece) // 16):
                    plain_t = np.reshape(np.array([elem for elem in piece[16 * i:16 * (i + 1)]]), (4, 4))

                    if self.mode == "CBC":
                        plain_t = plain_t ^ self.xor_factor

                    self.cipher(plain_t, key)
                    self.xor_factor = self.state

                    for elem in self.state.flatten():
                        cipher.append(elem)
                out_file.write(cipher)

    def decipher_text_file(self, filename, key):
       
        self.xor_factor = self.iv
        with open(filename, "rb") as in_file, open('decipher.txt', 'w', encoding="ascii") as out_file:
            while True:
                piece = in_file.read(self.chunk_size)
                if piece == b'':
                    break  # end of file
                out_text = ""
                for i in range(0, len(piece) // 16):
                    cipher_t = np.reshape(np.array([elem for elem in piece[16 * i:16 * (i + 1)]]), (4, 4))
                    self.decipher(cipher_t.copy(), key)

                    if self.mode == "CBC":
                        deciph = self.state ^ self.xor_factor
                    elif self.mode == "ECB":
                        deciph = self.state
                    self.xor_factor = cipher_t

                    out_text += ''.join(chr(x) for x in deciph.flatten())

                if in_file.peek(self.chunk_size) == b'':
                    out_text = self.remove_PKCS7_padding(out_text)
                out_file.write(out_text)
