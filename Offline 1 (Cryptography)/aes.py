import numpy as np
from BitVector import BitVector
from crypto_helper import *
from bitvector_demo import Sbox, InvSbox, Mixer, InvMixer
import time

AES_modulus = BitVector(bitstring='100011011')

key_expanded = False

# the following will hold the first constant, since the last three are 0 always
round_constants = np.zeros(15, dtype=np.uint8)
round_keys = np.zeros((64, 4), dtype=np.uint8)

# key will be a byte array


def schedule_key(key, key_size):
    key = fix_key(key, key_size)
    assert len(key) == key_size // 8
    n_rounds = 10 if key_size == 128 else 12 if key_size == 192 else 14

    global round_keys  # array of key matrices
    global key_expanded

    round_constants[1] = 0x01
    for round in range(2, 15):
        if round_constants[round - 1] < 0x80:
            round_constants[round] = round_constants[round - 1] << 1
        else:
            round_constants[round] = (
                round_constants[round - 1] << 1) ^ 0x11B

    # so now the first 4 (or 6 or 8) words of the round key are placed

    key_length_in_word = key_size // 32

    # https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
    # https://en.wikipedia.org/wiki/AES_key_schedule
    for i in range(len(key)):
        round_keys[i // 4][i % 4] = key[i]

    for idx in range(0, 4 * (n_rounds + 1)):
        if idx < key_length_in_word:
            round_keys[idx] = [key[idx * 4 + i] for i in range(4)]
        elif idx % key_length_in_word == 0:
            res = np.roll(round_keys[idx - 1], -1)
            res = substitute_bytes(res, Sbox)
            res = np.bitwise_xor(res, np.array(
                [round_constants[idx // key_length_in_word], 0, 0, 0]))
            round_keys[idx] = np.bitwise_xor(
                res, round_keys[idx - key_length_in_word])
        elif key_length_in_word > 6 and idx % key_length_in_word == 4:
            res = substitute_bytes(round_keys[idx - 1], Sbox)
            round_keys[idx] = np.bitwise_xor(
                res, round_keys[idx - key_length_in_word])
        else:
            round_keys[idx] = np.bitwise_xor(
                round_keys[idx - 1], round_keys[idx - key_length_in_word])

        # print("Iteration " + str(idx) + ": ")
        # print_hex_array(round_keys[idx])

        idx += 1

    key_expanded = True

    return


def generate_key_matrix(round):
    # the key matrix will be of 4x4 size
    key_matrix = np.zeros((4, 4), dtype=np.uint8)
    for i in range(4):
        key_matrix[:, i] = round_keys[4 * round + i]
    return key_matrix


def galois_multiplication(A, B, rowA, rowB, colB):
    result = np.zeros((rowA, colB), dtype=np.uint8)
    for i in range(rowA):
        for j in range(colB):
            for k in range(rowB):
                result[i][j] ^= A[i][k].gf_multiply_modular(
                    BitVector(hexstring=hex(B[k][j])[2:]), AES_modulus, 8).intValue()

    return result

# data will be a byte array


def AES_encryption(data, AES_key_size):
    assert len(data) == 16
    n_rounds = 10 if AES_key_size == 128 else 12 if AES_key_size == 192 else 14
    state_matrix = bytes_to_matrix(data)
    key_matrix = generate_key_matrix(0)

    # print_round_details(0, state_matrix, key_matrix)
    # Round 0
    state_matrix = np.bitwise_xor(state_matrix, key_matrix)

    for round in range(1, n_rounds + 1):
        key_matrix = generate_key_matrix(round)

        # print_round_details(round, state_matrix, key_matrix)

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
        if round != n_rounds:
            state_matrix = galois_multiplication(Mixer, state_matrix, 4, 4, 4)
            # print("After Mix Columns:")
            # print_hex_matrix(state_matrix)

        # Add Roundkey (XOR)
        state_matrix = np.bitwise_xor(state_matrix, key_matrix)

        # print("After Round Key:")
        # print_hex_matrix(state_matrix)

    cipher_data = matrix_to_bytes(state_matrix)
    return cipher_data

# cipher_data will be a byte array


def AES_decryption(cipher_data, AES_key_size):
    assert len(cipher_data) == 16
    n_rounds = 10 if AES_key_size == 128 else 12 if AES_key_size == 192 else 14
    state_matrix = bytes_to_matrix(cipher_data)
    key_matrix = generate_key_matrix(n_rounds)

    # Round 10
    state_matrix = np.bitwise_xor(state_matrix, key_matrix)

    for round in range(1, n_rounds + 1):
        key_matrix = generate_key_matrix(n_rounds - round)

        # print_round_details(round + 1, state_matrix, key_matrix)

        # Inverse Shift Rows
        for row in range(state_matrix.shape[0]):
            state_matrix[row] = np.roll(state_matrix[row], row, axis=0)

        # Inverse Substitute bytes
        state_matrix = substitute_bytes(state_matrix, InvSbox)

        # Add Roundkey (XOR)
        state_matrix = np.bitwise_xor(state_matrix, key_matrix)

        # Inverse Mix Columns
        if round != n_rounds:
            state_matrix = galois_multiplication(
                InvMixer, state_matrix, 4, 4, 4)

    plaintext = matrix_to_bytes(state_matrix)
    return plaintext

# both data and key will be byte arrays


def encrypt(data, key, init_vector, key_size):
    if not key_expanded:
        schedule_key(key, key_size)
    data = pad_bytes(data, False)
    # print("Before Encryption After Padding:")
    # print_hex_byte_string(data)

    # split the data into 16 byte blocks
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    cipher_data = np.zeros(len(data), dtype=np.uint8)
    vector = init_vector
    idx = 0
    for block in blocks:
        vector = AES_encryption(xor_bytes(block, vector), key_size)
        cipher_data[idx:idx + 16] = vector.copy()
        idx += 16

    # print("After Encryption:")
    # print_hex_byte_string(cipher_data)

    return cipher_data

# both cipher and key will be byte arrays


def decrypt(cipher_data, key, init_vector, key_size):
    if not key_expanded:
        schedule_key(key, key_size)

    # print("Before Decryption:")
    # print_hex_byte_string(cipher_data)

    blocks = [cipher_data[i:i + 16] for i in range(0, len(cipher_data), 16)]
    data = np.zeros(len(cipher_data), dtype=np.uint8)
    vector = init_vector
    idx = 0

    for block in blocks:
        result = xor_bytes(AES_decryption(block, key_size), vector)
        vector = block
        data[idx:idx + 16] = result.copy()
        idx += 16

    # print("After Decryption Before Unpadding:")
    # print_hex_byte_string(data)
    data = unpad_bytes(data, False)
    return data


if __name__ == "__main__":
    AES_key_size = int(input("Enter AES Key Size (128, 192, 256 bits): "))

    # inp1 = "Thats my Kung Fu"
    # inp2 = "Two One Nine Two"
    # inp1 = "BUET CSE19 Batch"
    # inp2 = "Never Gonna Give you up"

    inp1 = input("Enter Key: ")
    inp2 = input("Enter Message: ")

    key = string_to_bytes(inp1)
    key = fix_key(key, AES_key_size)
    message = string_to_bytes(inp2)

    print_text_details("Key", key, True)
    print_text_details("Plain Text", message, True)

    # s = "Thats my Kung Fu"
    # initialization_vector = string_to_bytes(s)
    initialization_vector = np.array([0] * 16, dtype=np.uint8)

    # Key Schedule
    t1 = time.time()
    schedule_key(key, AES_key_size)
    schedule_time = (time.time() - t1) * 1000

    # Encryption
    t1 = time.time()
    cipher = encrypt(message, key, initialization_vector, AES_key_size)
    cipher_time = (time.time() - t1) * 1000

    # Decryption
    t1 = time.time()
    deciphered = decrypt(cipher, key, initialization_vector, AES_key_size)
    decipher_time = (time.time() - t1) * 1000

    print("AES-" + str(AES_key_size) + " Encryption:\n")
    print_text_details("Ciphered Text", cipher, False)
    print_text_details("Deciphered Text", deciphered, False)

    print("Execution Time Details:")
    print("Key Schedule Time:", schedule_time, "ms")
    print("Encryption Time:", cipher_time, "ms")
    print("Decryption Time:", decipher_time, "ms")
