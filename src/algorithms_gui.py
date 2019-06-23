import sys
from PyQt4 import QtGui
from PyQt4 import QtCore
from Aes import Aes
from Des import Des
from RC6 import RC6
import numpy as np
import os


class Gui(QtCore.QObject):
    def __init__(self):
        super(Gui, self).__init__()
        self.app = QtGui.QApplication(sys.argv)
        self.main_window = QtGui.QWidget()
        self.main_window.setWindowTitle("Encryption algorithms")
        self.main_layout = QtGui.QVBoxLayout()
        self.create_alg_selector()
        self.create_encryption_selector()
        self.create_operational_mode_selector()
        self.create_file_selector()
        self.create_key_dialog()
        key = [np.uint8(int.from_bytes(os.urandom(1), sys.byteorder)) for _ in range(0, 16)]
        des_key = [0x1, 0x3, 0x3, 0x4, 0x5, 0x7, 0x7, 0x9, 0x9, 0xb, 0xb, 0xc, 0xd, 0xf, 0xf, 0x1]
        self.aes = Aes(np.reshape(key, (4, 4)), "CBC", 16)
        self.des = Des(des_key, "ECB", 8)
        self.rc6 = RC6(key, "ECB", 16, 20)

        self.main_layout.addLayout(self.file_selector_label_layout)
        self.main_layout.addLayout(self.key_label_layout)
        self.main_layout.addLayout(self.enc_label_layout)
        self.main_layout.addLayout(self.button_layout)
        self.main_layout.addLayout(self.mode_label_layout)
        self.run_button = QtGui.QPushButton("Run")
        self.run_button.clicked.connect(self.runFunction)
        self.main_layout.addWidget(self.run_button)
        self.main_window.setLayout(self.main_layout)
        self.main_window.show()

    def create_alg_selector(self):
        self.button_layout = QtGui.QVBoxLayout()
        self.button_label = QtGui.QLabel("Choose algorithm")
        self.button_layout.addWidget(self.button_label)
        self.algorithm_selector = QtGui.QButtonGroup(self.main_window)
        self.aes_button = QtGui.QRadioButton("Aes")
        self.aes_button.click()
        self.des_button = QtGui.QRadioButton("Des")
        self.rc6_button = QtGui.QRadioButton("RC6")
        self.group_button_lay = QtGui.QHBoxLayout()
        buttons = [self.aes_button, self.des_button, self.rc6_button]

        for button in buttons:
            self.algorithm_selector.addButton(button)
            self.group_button_lay.addWidget(button)
        self.button_layout.addLayout(self.group_button_lay)

    def create_encryption_selector(self):
        self.enc_label_layout = QtGui.QVBoxLayout()
        self.enc_label = QtGui.QLabel("Encryption or Decryption")
        self.enc_label_layout.addWidget(self.enc_label)
        self.enc_selector = QtGui.QButtonGroup(self.main_window)
        self.enc_button = QtGui.QRadioButton("Encryption")
        self.enc_button.click()
        self.dec_button = QtGui.QRadioButton("Decryption")
        buttons = [self.enc_button, self.dec_button]
        self.enc_button_lay = QtGui.QVBoxLayout()

        for button in buttons:
            self.enc_selector.addButton(button)
            self.enc_button_lay.addWidget(button)
        self.enc_label_layout.addLayout(self.enc_button_lay)

    def create_operational_mode_selector(self):
        self.mode_label_layout = QtGui.QVBoxLayout()
        self.mode_label = QtGui.QLabel("Operation mode")
        self.mode_label_layout.addWidget(self.mode_label)
        self.mode_selector = QtGui.QButtonGroup(self.main_window)
        self.ecb_button = QtGui.QRadioButton("ECB")
        self.ecb_button.click()
        self.cbc_button = QtGui.QRadioButton("CBC")
        self.change_mode_button = QtGui.QPushButton("Change mode")
        self.change_mode_button.clicked.connect(self.changeOperationalMode)
        buttons = [self.ecb_button, self.cbc_button]
        self.mode_button_lay = QtGui.QHBoxLayout()

        for button in buttons:
            self.mode_selector.addButton(button)
            self.mode_button_lay.addWidget(button, 0)
        self.mode_button_lay.addWidget(self.change_mode_button)
        self.mode_label_layout.addLayout(self.mode_button_lay)


    def create_file_selector(self):
        self.file_selector_label_layout = QtGui.QVBoxLayout()
        self.file_selector_label = QtGui.QLabel("Choose file")
        self.file_selector_label_layout.addWidget(self.file_selector_label)

        self.file_selector_layout = QtGui.QHBoxLayout()
        self.file_selector_button = QtGui.QPushButton("Browse")
        self.file_selector_button.clicked.connect(self.getFiles)
        self.path_viewer = QtGui.QTextEdit()
        self.path_viewer.setEnabled(False)
        self.path_viewer.setFixedSize(400, 50)

        self.file_selector_layout.addWidget(self.path_viewer)
        self.file_selector_layout.addWidget(self.file_selector_button)

        self.file_selector_label_layout.addLayout(self.file_selector_layout)

    def getFiles(self):
        dlg = QtGui.QFileDialog()
        dlg.setFileMode(QtGui.QFileDialog.AnyFile)
        dlg.setFilter("Text files (*.txt)")

        if dlg.exec_():
            self.current_filename = dlg.selectedFiles()
            self.path_viewer.setText(self.current_filename[0])

    def changeOperationalMode(self):
        print("Elo")

    def changeKey(self):
        print("Key changed")

    def create_key_dialog(self):
        self.key_label_layout = QtGui.QVBoxLayout()
        self.key_label = QtGui.QLabel("Type secret key (16 characters)")
        self.key_label_layout.addWidget(self.key_label)

        self.key_input_layout = QtGui.QHBoxLayout()
        self.key_input = QtGui.QLineEdit()
        self.key_input.setMaxLength(16)
        self.key_change_button = QtGui.QPushButton("Change key")
        self.key_change_button.clicked.connect(self.changeKey)

        self.key_input_layout.addWidget(self.key_input)
        self.key_input_layout.addWidget(self.key_change_button)

        self.key_label_layout.addLayout(self.key_input_layout)

    def runFunction(self):
        self.aes.cipher_text_file(self.current_filename[0])
        self.aes.decipher_text_file("cipher.txt")
        print("Ended")



if __name__ == "__main__":
    gui = Gui()
    sys.exit(gui.app.exec_())
