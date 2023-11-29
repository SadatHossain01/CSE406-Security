import numpy as np
from BitVector import *
from bitvector_demo import Sbox, Mixer

round_constant = np.array([0x01, 0x00, 0x00, 0x00])
AES_modulus = BitVector(bitstring='100011011')
n_rounds = 10


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


def string_to_matrix(str):
    # construct a 4x4 matrix of uint8 data type from the string
    assert len(str) == 16
    mat = np.zeros((4, 4), dtype=np.uint8)
    mat = [[ord(str[i * 4 + j]) for j in range(4)] for i in range(4)]
    # transpose the matrix to get the column major orientation
    mat = np.transpose(mat)
    return mat


def substitute_bytes(arr, sbox):
    # arr can be 1D or 2D
    flat_array = arr.flatten()
    substituted = np.array([sbox[val] for val in flat_array])
    substituted = substituted.reshape(arr.shape)
    return substituted


def expand_key(round, key_matrix):
    # Circular byte left shift the 4th column (upper shift)
    res = np.roll(key_matrix[:, -1], -1)

    # Byte substitution
    res = substitute_bytes(res, Sbox)

    # Fix the round constant
    if round == 1:
        round_constant[0] = 0x01
    elif round_constant[0] < 0x80:
        round_constant[0] <<= 1
    else:
        round_constant[0] = (round_constant[0] << 1) ^ 0x11B

    # Adding the round constant
    res = np.bitwise_xor(res, round_constant)

    for col in range(4):
        key_matrix[:, col] = np.bitwise_xor(key_matrix[:, col], res)
        # print_hex_array(key_matrix[:, col])
        res = key_matrix[:, col]

    # Round key obtained
    return key_matrix


def matrix_to_string(mat):
    # transpose the matrix to get the row major orientation
    mat = np.transpose(mat)
    str = ""
    for row in mat:
        for val in row:
            str += chr(val)
    return str


def AES_encryption(plaintext, key):
    assert len(plaintext) == 16 and len(key) == 16
    key_matrix = string_to_matrix(key)
    state_matrix = string_to_matrix(plaintext)

    # Round 0
    state_matrix = np.bitwise_xor(state_matrix, key_matrix)

    for round in range(n_rounds):
        key_matrix = expand_key(round + 1, key_matrix)
        # print("Round", round + 1)
        # print("State Matrix: ")
        # print_hex_matrix(state_matrix)
        # print("Round Key Matrix: ")
        # print_hex_matrix(key_matrix)

        # Substitute bytes
        state_matrix = substitute_bytes(state_matrix, Sbox)

        # print("After Substitute Byte:")
        # print_hex_matrix(state_matrix)

        # Shift Rows
        for row in range(state_matrix.shape[0]):
            state_matrix[row] = np.roll(state_matrix[row], -row, axis=0)

        # print("After Shift Rows:")
        # print_hex_matrix(state_matrix)

        # Mix Columns
        if round != n_rounds - 1:
            result = np.zeros((4, 4), dtype=np.uint8)
            for i in range(4):
                for j in range(state_matrix.shape[1]):
                    for k in range(4):
                        result[i][j] ^= Mixer[i][k].gf_multiply_modular(
                            BitVector(hexstring=hex(state_matrix[k][j])[2:]), AES_modulus, 8).intValue()

            state_matrix = result
            # print("After Mix Columns:")
            # print_hex_matrix(state_matrix)

        # Add Roundkey (XOR)
        state_matrix = np.bitwise_xor(state_matrix, key_matrix)

        # print("After Round Key:")
        # print_hex_matrix(state_matrix)

    ciphertext = matrix_to_string(state_matrix)
    return ciphertext


def encrypt(message, key):
    while len(message) % 16 != 0:
        message += "\0"

    # split the message into 16 byte blocks
    blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
    ciphertext = ""
    for block in blocks:
        ciphertext += AES_encryption(block, key)
    return ciphertext


print(encrypt("Never Gonna Give you up", "BUET CSE19 Batch"))
