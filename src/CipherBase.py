import numpy as np


class CipherBase:

    def __init__(self):
        self.state = np.array(np.zeros((4, 4)))

    def cipher(self):
        pass

    def decipher(self):
        pass

    def round(self):
        pass

    def readFile(self):
        pass

    def append_PKCS7_padding(self, data):
        pad = 16 - (len(data) % 16)
        byt = bytes([ord(c) for c in ((chr(pad) * pad))])
        return data + byt

    def remove_PKCS7_padding(self, data):
        if len(data) % 16 != 0:
            raise ValueError("Data not padded properly")

        pad = ord(data[-1])

        if pad > 16:
            raise ValueError("Pad has too big value")

        return data[:-pad]

    def cipher_text_file(self, filename, key):

        with open(filename, "rb") as in_file, open('cipher.txt', 'wb') as out_file:
            while True:
                piece = in_file.read(self.chunk_size)
                if piece == b'':
                    break  # end of file
                cipher = bytearray()
                piece = self.append_PKCS7_padding(piece)

                for i in range(0, len(piece) // 16):
                    plain_t = np.reshape(np.array([elem for elem in piece[16 * i:16 * (i + 1)]]), (4, 4))
                    self.cipher(plain_t, key)
                    for elem in self.state.flatten():
                        cipher.append(elem)
                out_file.write(cipher)

    def decipher_text_file(self, filename, key):
        with open(filename, "rb") as in_file, open('decipher.txt', 'w') as out_file:
            while True:
                piece = in_file.read(self.chunk_size)
                if piece == b'':
                    break  # end of file
                out_text = ""
                for i in range(0, len(piece) // 16):
                    cipher_t = np.reshape(np.array([elem for elem in piece[16 * i:16 * (i + 1)]]), (4, 4))
                    self.decipher(cipher_t, key)
                    out_text += ''.join(chr(x) for x in self.state.flatten())
                out_file.write(self.remove_PKCS7_padding(out_text))
