import numpy as np
from BitVector import BitVector
from helper import *
from bitvector_demo import Sbox, InvSbox, Mixer, InvMixer

AES_modulus = BitVector(bitstring='100011011')
AES_key_size = 256  # can be 128, 192, or 256 bits
n_rounds = 0
# initialization_vector = "\x00" * 16

key_expanded = False

# the following will hold the first constant, since the last three are 0 always
round_constants = np.zeros(15, dtype=np.uint8)
round_keys = np.zeros((64, 4), dtype=np.uint8)


def schedule_key(key):
    key = fix_key(key, AES_key_size // 8)
    assert len(key) == AES_key_size // 8
    global n_rounds
    n_rounds = 10 if AES_key_size == 128 else 12 if AES_key_size == 192 else 14

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

    key_length_in_word = AES_key_size // 32

    # https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
    # https://en.wikipedia.org/wiki/AES_key_schedule
    for i in range(len(key)):
        round_keys[i // 4][i % 4] = ord(key[i])

    for idx in range(0, 4 * (n_rounds + 1)):
        if idx < key_length_in_word:
            round_keys[idx] = [ord(key[idx * 4 + i]) for i in range(4)]
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


def AES_encryption(plaintext):
    assert len(plaintext) == 16
    state_matrix = string_to_matrix(plaintext)
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

    ciphertext = matrix_to_string(state_matrix)
    return ciphertext


def AES_decryption(ciphertext):
    assert len(ciphertext) == 16
    state_matrix = string_to_matrix(ciphertext)
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

    plaintext = matrix_to_string(state_matrix)
    return plaintext


def encrypt(message, key, init_vector, key_size):
    global AES_key_size
    AES_key_size = key_size
    if not key_expanded:
        schedule_key(key)

    message = pad_string(message, False)
    # print("Before Encryption After Padding:")
    # print_hex_string(message)

    # split the message into 16 byte blocks
    blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
    ciphertext = ""
    vector = init_vector
    for block in blocks:
        vector = AES_encryption(xor_strings(block, vector))
        ciphertext += vector
    return ciphertext


def decrypt(cipher, key, init_vector, key_size):
    global AES_key_size
    AES_key_size = key_size
    if not key_expanded:
        schedule_key(key)
    blocks = [cipher[i:i + 16] for i in range(0, len(cipher), 16)]
    plaintext = ""
    vector = init_vector
    for block in blocks:
        result = xor_strings(AES_decryption(block), vector)
        vector = block
        plaintext += result

    # print("After Decryption Before Unpadding:")
    # print_hex_string(plaintext)
    plaintext = unpad_string(plaintext, False)

    return plaintext


if __name__ == "__main__":
    AES_key_size = int(input("Enter AES Key Size (128, 192, 256): "))
    # key = "BUET CSE19 Batch 2023 Fall Semester"
    # message = "Never Gonna Give You Up"
    # key = "Thats my Kung Fu"
    # message = "Two One Nine Two"

    key = input("Enter Key: ")
    message = input("Enter Message: ")

    key = fix_key(key, AES_key_size // 8)
    print("AES-" + str(AES_key_size) + " Encryption")
    print_text_details("Key", key, True)
    print_text_details("Plain Text", message, True)

    any, schedule_time = measure_execution_time(
        schedule_key, "Key Schedule", key)
    cipher, cipher_time = measure_execution_time(
        encrypt, "Encryption", message)
    deciphered, decipher_time = measure_execution_time(
        decrypt, "Decryption", cipher)

    print_text_details("Ciphered Text", cipher, False)
    print_text_details("Deciphered Text", deciphered, False)

    print("Execution Time Details:")
    print("Key Schedule Time:", schedule_time, "ms")
    print("Encryption Time:", cipher_time, "ms")
    print("Decryption Time:", decipher_time, "ms")
