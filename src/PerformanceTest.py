from Aes import Aes
from RC6 import RC6
from Des import Des
import matplotlib.pyplot as plt
import numpy as np
import os
import sys
import time
import pickle


def create_test_files():
    for i in range(0, 1024*1024*1+1, 1024*10):
        file_name = '../test/test_file' + str(i//1024).zfill(4) + "_kbytes.txt"
        file_size = i if i else 1024  # size in bytes
        with open(file_name, "wb") as f:
            f.write(os.urandom(file_size))

def test_algorithms():
    key = [int.from_bytes(os.urandom(1), sys.byteorder) for _ in range(0, 16)]
    des_key = [0x1, 0x3, 0x3, 0x4, 0x5, 0x7, 0x7, 0x9, 0x9, 0xb, 0xb, 0xc, 0xd, 0xf, 0xf, 0x1]
    aes = Aes(np.reshape(key, (4, 4)), "CBC", 16)
    des = Des(des_key, "CBC", 8)
    rc6 = RC6(key, "CBC", 16, 20)
    perf_dict = {str(type(aes)): [], str(type(des)): [], str(type(rc6)): []}
    test_path = "../test/"
    algorithms = [aes, des, rc6]
    for algorithm in algorithms:
        print("Computing algorithm {0}".format(type(algorithm)))
        i = 0
        for file in os.listdir(test_path):
            print("Progress {0} out of {1}".format(i, len(os.listdir(test_path))))
            start = time.time()
            algorithm.cipher_text_file(test_path + file)
            end = time.time()
            time_exec = end - start
            perf_dict[str(type(algorithm))].append(time_exec)
            i += 1

    with open('performance_data.p', 'wb') as fp:
        pickle.dump(perf_dict, fp, protocol=pickle.HIGHEST_PROTOCOL)


def make_charts(do_save=False):
    step = [item for item in range(10, 1021, 10)]
    step.insert(0, 1)
    try:
        with open('performance_data.p', 'rb') as fp:
            data = pickle.load(fp)
            print(data)
            for key, perf_data in data.items():
                plt.figure()
                plt.xlabel("File size [KB]")
                plt.ylabel("Encryption time [s]")
                plt.title("Execution time for algorithm {0}".format(key.split(".")[1].split("'")[0]))
                plt.plot(step, perf_data)
                if do_save:
                    plt.savefig("Perf_{0}".format(key.split(".")[1].split("'")[0]))
                plt.show()
    except EnvironmentError:
        test_algorithms()
        make_charts()


def make_subplot_charts(do_save=False):
    step = [item for item in range(10, 1021, 10)]
    step.insert(0, 1)
    try:
        with open('performance_data.p', 'rb') as fp:
            data = pickle.load(fp)
            plt.figure()
            plt.xlabel("File size [KB]")
            plt.ylabel("Encryption time [s]")
            plt.title("Execution time for algorithms")
            colors = ['r', 'g', 'b']
            labels = []
            for i, (key, perf_data) in enumerate(data.items()):
                plt.plot(step, perf_data, colors[i])
                labels.append("{0}".format(key.split(".")[1].split("'")[0]))

            plt.legend(labels)
            if do_save:
                plt.savefig("Perf_combined")
            plt.show()
    except EnvironmentError:
        test_algorithms()
        make_subplot_charts()


def make_noised_charts(do_save=False):
    step = [item for item in range(10, 1021, 10)]
    step.insert(0, 1)
    try:
        with open('performance_data_noised.p', 'rb') as fp:
            data = pickle.load(fp)
            for key, perf_data in data.items():
                plt.figure()
                plt.xlabel("File size [KB]")
                plt.ylabel("Encryption time [s]")
                plt.title("Execution time for algorithm {0}".format(str(key).split(".")[1].split("'")[0]))
                plt.plot(step, perf_data)
                if do_save:
                    plt.savefig("Perf_noised_{0}".format(str(key).split(".")[1].split("'")[0]))
                plt.show()
    except EnvironmentError:
        print("No noised data found")


if __name__ == "__main__":
    make_charts()
    make_subplot_charts()
    make_noised_charts()


"""
    import time
    start = time.time()
    
    end = time.time()
    print(end - start)
"""
