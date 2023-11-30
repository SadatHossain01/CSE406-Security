import numpy as np


def print_hex_string(str):
    for char in str:
        if ord(char) < 16:
            print("0", end="")
        print(hex(ord(char))[2:].upper(), end=" ")
    print()


def print_hex_array(arr):
    # arr is 1D
    for val in arr:
        if val < 16:
            print("0", end="")
        print(hex(val)[2:].upper(), end=" ")
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


def print_text_details(title, str, ascii_first):
    print(title + ":")
    if ascii_first:
        print("In ASCII:", str)
        print("In HEX: ", end="")
        print_hex_string(str)
    else:
        print("In HEX:", str)
        print("In ASCII: ", end="")
        print_hex_string(str)
    print()


def string_to_matrix(str):
    # construct a 4x4 matrix of uint8 data type from the string
    assert len(str) == 16
    mat = np.zeros((4, 4), dtype=np.uint8)
    mat = [[ord(str[i * 4 + j]) for j in range(4)] for i in range(4)]
    # transpose the matrix to get the column major orientation
    mat = np.transpose(mat)
    return mat


def matrix_to_string(mat):
    # transpose the matrix to get the row major orientation
    mat = np.transpose(mat)
    str = ""
    for row in mat:
        for val in row:
            str += chr(val)
    return str


def measure_execution_time(func, task_name, *args, **kwargs):
    import time
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    return result, (end - start) * 1000


def xor_strings(str1, str2):
    assert len(str1) == len(str2)
    result = ""
    for i in range(len(str1)):
        result += chr(ord(str1[i]) ^ ord(str2[i]))
    return result


def substitute_bytes(arr, src):
    # arr can be 1D or 2D
    flat_array = arr.flatten()
    substituted = np.array([src[val] for val in flat_array])
    substituted = substituted.reshape(arr.shape)
    return substituted


def pad_string(str):
    if len(str) % 16 == 0:
        # pad with an entire dummy block of 0s (16 bytes)
        str += "\x00" * 16
    else:
        rem = 16 - len(str) % 16
        str += chr(rem) * rem
    return str


def unpad_string(str):
    # remove the padding
    assert len(str) % 16 == 0
    if str[-1] == 0x00:
        # remove the entire dummy block
        return str[:-16]
    else:
        # remove the padding
        return str[:-ord(str[-1])]
