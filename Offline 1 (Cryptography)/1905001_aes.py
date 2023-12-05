import numpy as np
from BitVector import BitVector
import time
import importlib
import threading
import copy

crypto_helper = importlib.import_module("1905001_crypto_helper")

AES_modulus = BitVector(bitstring='100011011')

key_expanded = False

# the following will hold the first constant, since the last three are 0 always
round_constants = np.zeros(15, dtype=np.uint8)
round_keys = np.zeros((64, 4), dtype=np.uint8)


def schedule_key(key, key_size):
    """
    key: a byte array
    """
    key = crypto_helper.fix_key(key, key_size)
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
            res = crypto_helper.substitute_bytes(res, crypto_helper.Sbox)
            res = np.bitwise_xor(res, np.array(
                [round_constants[idx // key_length_in_word], 0, 0, 0]))
            round_keys[idx] = np.bitwise_xor(
                res, round_keys[idx - key_length_in_word])
        elif key_length_in_word > 6 and idx % key_length_in_word == 4:
            res = crypto_helper.substitute_bytes(
                round_keys[idx - 1], crypto_helper.Sbox)
            round_keys[idx] = np.bitwise_xor(
                res, round_keys[idx - key_length_in_word])
        else:
            round_keys[idx] = np.bitwise_xor(
                round_keys[idx - 1], round_keys[idx - key_length_in_word])

        # print("Iteration " + str(idx) + ": ")
        # crypto_helper.print_hex_array(round_keys[idx])

        idx += 1

    key_expanded = True

    return


def generate_key_matrix(round):
    """
    key_matrix: a 4x4 numpy array of uint8
    """
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


def AES_encryption(data, AES_key_size):
    """
    data: a byte array
    """
    assert len(data) == 16
    n_rounds = 10 if AES_key_size == 128 else 12 if AES_key_size == 192 else 14
    state_matrix = crypto_helper.bytes_to_matrix(data)
    key_matrix = generate_key_matrix(0)

    # crypto_helper.print_round_details(0, state_matrix, key_matrix)
    # Round 0
    state_matrix = np.bitwise_xor(state_matrix, key_matrix)

    for round in range(1, n_rounds + 1):
        key_matrix = generate_key_matrix(round)

        # crypto_helper.print_round_details(round, state_matrix, key_matrix)

        # Substitute bytes
        state_matrix = crypto_helper.substitute_bytes(
            state_matrix, crypto_helper.Sbox)

        # print("After Substitute Byte:")
        # crypto_helper.print_hex_matrix(state_matrix)

        # Shift Rows
        for row in range(state_matrix.shape[0]):
            state_matrix[row] = np.roll(state_matrix[row], -row, axis=0)

        # print("After Shift Rows:")
        # crypto_helper.print_hex_matrix(state_matrix)

        # Mix Columns
        if round != n_rounds:
            state_matrix = galois_multiplication(
                crypto_helper.Mixer, state_matrix, 4, 4, 4)
            # print("After Mix Columns:")
            # crypto_helper.print_hex_matrix(state_matrix)

        # Add Roundkey (XOR)
        state_matrix = np.bitwise_xor(state_matrix, key_matrix)

        # print("After Round Key:")
        # crypto_helper.print_hex_matrix(state_matrix)

    cipher_data = crypto_helper.matrix_to_bytes(state_matrix)
    return cipher_data


def AES_decryption(cipher_data, AES_key_size):
    """
    cipher_data: a byte array
    """
    assert len(cipher_data) == 16
    n_rounds = 10 if AES_key_size == 128 else 12 if AES_key_size == 192 else 14
    state_matrix = crypto_helper.bytes_to_matrix(cipher_data)
    key_matrix = generate_key_matrix(n_rounds)

    # Round 10
    state_matrix = np.bitwise_xor(state_matrix, key_matrix)

    for round in range(1, n_rounds + 1):
        key_matrix = generate_key_matrix(n_rounds - round)

        # crypto_helper.print_round_details(round + 1, state_matrix, key_matrix)

        # Inverse Shift Rows
        for row in range(state_matrix.shape[0]):
            state_matrix[row] = np.roll(state_matrix[row], row, axis=0)

        # Inverse Substitute bytes
        state_matrix = crypto_helper.substitute_bytes(
            state_matrix, crypto_helper.InvSbox)

        # Add Roundkey (XOR)
        state_matrix = np.bitwise_xor(state_matrix, key_matrix)

        # Inverse Mix Columns
        if round != n_rounds:
            state_matrix = galois_multiplication(
                crypto_helper.InvMixer, state_matrix, 4, 4, 4)

    deciphered_data = crypto_helper.matrix_to_bytes(state_matrix)
    return deciphered_data


def CTR_block_encryption(block_data, nonce, key_size, array, idx):
    encrypted = AES_encryption(nonce, key_size)
    array[idx:idx + 16] = crypto_helper.xor_bytes(block_data, encrypted)


def CTR_encryption_decryption(blocks, init_vector, key_size):
    """
    blocks: plain data blocks for encryption, cipher data blocks for decryption
    Returns: cipher data blocks for encryption, plain data blocks for decryption
    """
    res_data = np.zeros(16 * len(blocks), dtype=np.uint8)
    nonce = init_vector
    idx = 0
    threads = []
    for block in blocks:
        t = threading.Thread(target=CTR_block_encryption,
                             args=(block, nonce, key_size, res_data, idx))
        threads.append(t)
        nonce = crypto_helper.add_scalar(nonce, 1)
        idx += 16
    [t.start() for t in threads]
    [t.join() for t in threads]
    return res_data


def CBC_encryption(blocks, init_vector, key_size):
    cipher_data = np.zeros(16 * len(blocks), dtype=np.uint8)
    vector = init_vector.copy()
    idx = 0
    for block in blocks:
        xored = crypto_helper.xor_bytes(block, vector)
        cipher_data[idx:idx + 16] = AES_encryption(xored, key_size)
        vector = np.copy(cipher_data[idx:idx + 16])
        idx += 16
    return cipher_data


def CBC_decryption(blocks, init_vector, key_size):
    deciphered_data = np.zeros(16 * len(blocks), dtype=np.uint8)
    vector = init_vector.copy()
    idx = 0
    for block in blocks:
        result = crypto_helper.xor_bytes(
            AES_decryption(block, key_size), vector)
        vector = copy.deepcopy(block)
        deciphered_data[idx:idx + 16] = result.copy()
        idx += 16
    return deciphered_data


def encrypt(data, key, init_vector, key_size, space_padding=False, ctr_mode=True):
    """
    data: a byte array
    key: a byte array
    Default: CTR mode, proper padding
    """
    if not key_expanded:
        schedule_key(key, key_size)
    data = crypto_helper.pad_bytes(data, space_padding)
    # print("Before Encryption After Padding:")
    # crypto_helper.print_hex_byte_string(data)

    # split the data into 16 byte blocks
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]

    cipher_data = CTR_encryption_decryption(blocks, np.copy(init_vector), key_size) if ctr_mode else CBC_encryption(
        blocks, np.copy(init_vector), key_size)

    # print("After Encryption:")
    # crypto_helper.print_hex_byte_string(cipher_data)

    return cipher_data


def decrypt(cipher_data, key, init_vector, key_size, space_padding=False, ctr_mode=True):
    """
    cipher_data: a byte array
    key: a byte array
    """
    if not key_expanded:
        schedule_key(key, key_size)

    # print("Before Decryption:")
    # crypto_helper.print_hex_byte_string(cipher_data)

    blocks = [cipher_data[i:i + 16] for i in range(0, len(cipher_data), 16)]

    data = CTR_encryption_decryption(blocks, np.copy(init_vector), key_size) if ctr_mode else CBC_decryption(
        blocks, np.copy(init_vector), key_size)

    # print("After Decryption Before Unpadding:")
    # crypto_helper.print_hex_byte_string(data)

    data = crypto_helper.unpad_bytes(data, space_padding)

    return data


if __name__ == "__main__":
    AES_key_size = int(input("Enter AES Key Size (128, 192, 256 bits): "))
    mode_choice = int(input("Enter Mode (1 for CTR, 2 for CBC): "))

    # inp1 = "Thats my Kung Fu"
    # inp2 = "Two One Nine Two"
    # inp1 = "BUET CSE19 Batch"
    # inp2 = "Never Gonna Give you up, Never"

    inp1 = input("Enter Key: ")
    inp2 = input("Enter Message: ")

    key = crypto_helper.string_to_bytes(inp1)
    key = crypto_helper.fix_key(key, AES_key_size)
    message = crypto_helper.string_to_bytes(inp2)

    # s = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    # initialization_vector = crypto_helper.string_to_bytes(s)
    initialization_vector = np.array([0] * 16, dtype=np.uint8)

    crypto_helper.print_text_details("Key", key, True)
    crypto_helper.print_text_details("Plain Text", message, True)
    crypto_helper.print_text_details("IV", initialization_vector, True)

    # Key Schedule
    t1 = time.time()
    schedule_key(key, AES_key_size)
    schedule_time = (time.time() - t1) * 1000

    # Encryption
    t1 = time.time()
    # Doing space padding for this task
    cipher = encrypt(message, key, initialization_vector,
                     AES_key_size, space_padding=True, ctr_mode=True if mode_choice == 1 else False)
    cipher_time = (time.time() - t1) * 1000

    # Decryption
    t1 = time.time()
    # Doing space padding for this task
    deciphered = decrypt(
        cipher, key, initialization_vector, AES_key_size, space_padding=True, ctr_mode=True if mode_choice == 1 else False)
    decipher_time = (time.time() - t1) * 1000

    print("AES-" + str(AES_key_size) + " Encryption (" +
          ("CTR" if mode_choice == 1 else "CBC") + " Mode): ")
    crypto_helper.print_text_details("Ciphered Text", cipher, False)
    crypto_helper.print_text_details("Deciphered Text", deciphered, False)

    print("Execution Time Details:")
    print("Key Schedule Time:", schedule_time, "ms")
    print("Encryption Time:", cipher_time, "ms")
    print("Decryption Time:", decipher_time, "ms")
