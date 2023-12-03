import numpy as np
import random
from sympy import nextprime


def print_byte_string(arr):
    for val in arr:
        print(chr(val), end="")
    print()


def print_hex_byte_string(arr):
    for val in arr:
        if val < 16:
            print("0", end="")
        print(hex(val)[2:], end=" ")
    print()


def print_hex_array(arr):
    # arr is 1D
    for val in arr:
        if val < 16:
            print("0", end="")
        print(hex(val)[2:], end=" ")
    print()


def print_hex_matrix(mat):
    for row in mat:
        print_hex_array(row)
    print()


def print_round_details(round, state_matrix, key_matrix):
    print("Round", round)
    print("State Matrix: ")
    print_hex_matrix(state_matrix)
    print("Round Key Matrix: ")
    print_hex_matrix(key_matrix)


def print_text_details(title, data, ascii_first):
    print(title + ":")
    if ascii_first:
        print("In ASCII:", end=" ")
        print_byte_string(data)
        print("In HEX: ", end="")
        print_hex_byte_string(data)
    else:
        print("In HEX: ", end="")
        print_hex_byte_string(data)
        print("In ASCII:", end=" ")
        print_byte_string(data)
    print()

# data will be a byte array


def bytes_to_matrix(data):
    # construct a 4x4 matrix of uint8 data type from the data
    assert len(data) == 16
    mat = np.zeros((4, 4), dtype=np.uint8)
    mat = [[data[i * 4 + j] for j in range(4)] for i in range(4)]
    # transpose the matrix to get the column major orientation
    mat = np.transpose(mat)
    return mat


def matrix_to_bytes(mat):
    # transpose the matrix to get the row major orientation
    mat = np.transpose(mat)
    res = np.zeros(16, dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            res[i * 4 + j] = mat[i][j]
    return res

# both arr1 and arr2 will be numpy arrays of uint8


def xor_bytes(arr1, arr2):
    assert len(arr1) == len(arr2)
    result = np.zeros(len(arr1), dtype=np.uint8)
    for i in range(len(arr1)):
        result[i] = arr1[i] ^ arr2[i]
    return result


def substitute_bytes(arr, src):
    # arr can be 1D or 2D
    flat_array = arr.flatten()
    substituted = np.array([src[val] for val in flat_array])
    substituted = substituted.reshape(arr.shape)
    return substituted

# data will be a byte array


def pad_bytes(data, space_padding=False):
    if (len(data) % 16 == 0 and space_padding):
        return data
    res = np.zeros(len(data) + (16 - len(data) % 16), dtype=np.uint8)
    res[:len(data)] = data
    if space_padding:
        res[len(data):] = ord(' ')
    else:
        if len(data) % 16 == 0:
            # pad with an entire dummy block of 0s (16 bytes)
            res[len(data):] = [0x00] * 16
        else:
            rem = 16 - len(data) % 16
            res[len(data):] = [rem] * rem
    return res

# data will be a byte array


def unpad_bytes(data, space_padding=False):
    # remove the padding
    assert len(data) % 16 == 0
    if space_padding:
        return data
    else:
        extra = data[-1] if data[-1] != 0 else 16
        length = len(data)
        return data[:length - extra]


def generate_prime(size_bits):
    # Generate a random number of the specified size
    num = random.getrandbits(size_bits)

    # Find the next prime number greater than or equal to the generated number
    prime = nextprime(num)

    return prime

# key will be a byte array
# expected size is in bits


def fix_key(key, expected_size):
    expected_bytes = expected_size // 8
    res = np.zeros(expected_bytes, dtype=np.uint8)
    for i in range(expected_bytes):
        res[i] = key[i % len(key)]
    return res

# returns a numpy array of uint8


def string_to_bytes(str):
    return np.array([ord(char) for char in str], dtype=np.uint8)


def bytes_to_string(arr):
    return "".join([chr(val) for val in arr])

# returns a numpy byte array of uint8, having length len (len bytes)
# if len is -1, then the length of the array is the minimum required to store the number


def int_to_bytes(num, len=-1):
    if len == -1:
        len = (num.bit_length() + 7) // 8
    bits = np.binary_repr(num, width=len * 8)
    res = np.zeros(len, dtype=np.uint8)
    for i in range(len):
        res[i] = int(bits[i * 8:(i + 1) * 8], 2)
    return res


def generate_iv():
    res = np.zeros(16, dtype=np.uint8)
    for i in range(16):
        res[i] = random.randint(0, 255)
    return res
