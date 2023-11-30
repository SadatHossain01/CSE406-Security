from pydoc import plain
import numpy as np
from BitVector import BitVector
from helper import *
from bitvector_demo import Sbox, InvSbox, Mixer, InvMixer

round_constant = np.array([0x01, 0x00, 0x00, 0x00])
AES_modulus = BitVector(bitstring='100011011')
AES_key_size = 256  # can be 128, 192, or 256 bits
n_rounds = None
if AES_key_size == 128:
    n_rounds = 10
elif AES_key_size == 192:
    n_rounds = 12
else:
    n_rounds = 14
# https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf (Page 44)
# will need 44, 52, or 60 words for key expansion (for 128, 192, and 256 bit keys respectively)
key_expanded = False
round_keys = np.zeros((64, 4), dtype=np.uint8)


def expand_key(round):
    # at the very first expansion round, round will be 1
    n_words_each_round = AES_key_size // 32

    # copy the last word
    res = round_keys[n_words_each_round * round - 1].copy()

    # Circular byte left shift
    res = np.roll(res, -1)

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

    for i in range(n_words_each_round):
        round_keys[n_words_each_round * round + i] = np.bitwise_xor(
            round_keys[n_words_each_round * (round - 1) + i], res)
        res = round_keys[n_words_each_round * round + i]

    return


def schedule_key(key):
    assert len(key) >= AES_key_size // 8
    key = key[:AES_key_size // 8]
    global round_keys  # array of key matrices
    global key_expanded

    n_words_each_round = AES_key_size // 32
    for i in range(len(key)):
        round_keys[i // 4][i % 4] = ord(key[i])

    # so now the first 4 (or 6 or 8) words of the round key are placed

    ready_words = n_words_each_round
    round = 1

    while ready_words < (n_rounds + 1) * 4:
        expand_key(round)
        ready_words += n_words_each_round
        round += 1

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

    # Round 0
    state_matrix = np.bitwise_xor(state_matrix, key_matrix)

    for round in range(n_rounds):
        key_matrix = generate_key_matrix(round + 1)

        # print_round_details(round + 1, state_matrix, key_matrix)

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

    # Round 0
    state_matrix = np.bitwise_xor(state_matrix, key_matrix)

    for round in range(n_rounds):
        key_matrix = generate_key_matrix(n_rounds - round - 1)

        # print_round_details(round + 1, state_matrix, key_matrix)

        # Inverse Shift Rows
        for row in range(state_matrix.shape[0]):
            state_matrix[row] = np.roll(state_matrix[row], row, axis=0)

        # Inverse Substitute bytes
        state_matrix = substitute_bytes(state_matrix, InvSbox)

        # Add Roundkey (XOR)
        state_matrix = np.bitwise_xor(state_matrix, key_matrix)

        # Inverse Mix Columns
        if round != n_rounds - 1:
            state_matrix = galois_multiplication(
                InvMixer, state_matrix, 4, 4, 4)

    plaintext = matrix_to_string(state_matrix)
    return plaintext


def encrypt(message):
    if not key_expanded:
        schedule_key(key)

    message = pad_string(message)
    # print("Before Encryption After Padding:")
    # print_hex_string(message)

    # split the message into 16 byte blocks
    blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
    ciphertext = ""
    for block in blocks:
        ciphertext += AES_encryption(block)
    return ciphertext


def decrypt(cipher):
    if not key_expanded:
        schedule_key(key)
    blocks = [cipher[i:i + 16] for i in range(0, len(cipher), 16)]
    plaintext = ""

    for block in blocks:
        plaintext += AES_decryption(block)

    # print("After Decryption Before Unpadding:")
    # print_hex_string(plaintext)
    plaintext = unpad_string(plaintext)

    return plaintext


key = "BUET CSE19 Batch 2023 Fall Semester"
message = "Never Gonna Give You Up Never Gonna Let You Down, Never Gonna Run Around And Desert You, Never Gonna Make You Cry Never Gonna Say Goodbye, Never Gonna Tell A Lie And Hurt You"

schedule_key(key)

# key = input("Enter Key: ")[:32]
# message = input("Enter Message: ")

print_text_details("Key", key, True)
print_text_details("Plain Text", message, True)


any, schedule_time = measure_execution_time(schedule_key, "Key Schedule", key)
cipher, cipher_time = measure_execution_time(encrypt, "Encryption", message)
deciphered, decipher_time = measure_execution_time(
    decrypt, "Decryption", cipher)

print_text_details("Ciphered Text", cipher, False)
print_text_details("Deciphered Text", deciphered, False)

print("Execution Time Details:")
print("Key Schedule Time:", schedule_time, "ms")
print("Encryption Time:", cipher_time, "ms")
print("Decryption Time:", decipher_time, "ms")
