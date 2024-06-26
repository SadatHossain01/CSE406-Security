import numpy as np
import importlib
import os

aes = importlib.import_module("1905001_aes")
crypto_helper = importlib.import_module("1905001_crypto_helper")


def send_ecc_params(a, b, x, y, p, key_size, pub_key, socket):
    params = str(a) + "|" + str(b) + "|" + str(x) + "|" + str(y) + "|" + str(p) + \
        "|" + str(key_size) + "|" + str(pub_key[0]) + "," + str(pub_key[1])
    socket.send(params.encode())


def receive_ecc_params(socket):
    params = socket.recv(8192).decode()
    stuffs = params.split('|')
    a = int(stuffs[0])
    b = int(stuffs[1])
    x = int(stuffs[2])
    y = int(stuffs[3])
    p = int(stuffs[4])
    key_size = int(stuffs[5])
    pub_key = (int(stuffs[6].split(',')[0]), int(stuffs[6].split(',')[1]))
    return a, b, x, y, p, key_size, pub_key


def send_text_message(text, socket, key, key_size):
    # First send a "text" string to indicate that the message is a text message
    socket.send("text".encode())
    iv = crypto_helper.generate_iv()
    encrypted_data = aes.encrypt(
        crypto_helper.string_to_bytes(text), key, iv, key_size)
    msg = crypto_helper.bytes_to_string(iv) + \
        crypto_helper.bytes_to_string(encrypted_data)
    socket.send(msg.encode())


def receive_text_message(socket, key, key_size):
    msg = socket.recv(8192).decode()
    iv = crypto_helper.string_to_bytes(msg[:16])
    encrypted_data = crypto_helper.string_to_bytes(msg[16:])
    decrypted_data = aes.decrypt(encrypted_data, key, iv, key_size)
    text = crypto_helper.bytes_to_string(decrypted_data)
    return text


def send_file(file_path, socket, key, key_size):
    # Read the file into a byte array
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
    except:
        print("File not found.")
        return

    # First send a "file" string to indicate that the message is a file, also send the file name
    ss = "file|" + file_path.split('/')[-1]
    socket.send(ss.encode())
    iv = crypto_helper.generate_iv()

    data = bytearray(file_data)
    encrypted_data = aes.encrypt(
        data, key, iv, key_size)
    socket.send(iv.tobytes() + encrypted_data.tobytes())

    print("File sent.")


def create_directory(directory_name):
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, directory_name)
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)
    return final_directory


def receive_file(socket, key, key_size, file_name):
    """
    Maximum file size: 1 MB
    """
    # Receive the file data
    data = bytes([])
    buffer = socket.recv(1048576)
    data += buffer
    # while buffer:
    #     data += buffer
    #     buffer = socket.recv(8192)

    print("Encrypted data length: " + str(len(data)) + " bytes")

    iv = np.zeros(16, dtype=np.uint8)
    encrypted_data = np.zeros(len(data) - 16, dtype=np.uint8)
    iv = [data[i] for i in range(16)]
    encrypted_data = [data[i] for i in range(16, len(data))]
    decrypted_data = aes.decrypt(encrypted_data, key, iv, key_size)

    print("Decrypted data length: " + str(len(decrypted_data)) + " bytes")

    download_directory = create_directory("Downloads")

    # write this byte array to a new file
    final_bytes = decrypted_data.tobytes()
    new_path = os.path.join(download_directory, file_name)
    with open(new_path, 'wb') as file:
        file.write(final_bytes)
    print("File received and saved to " + new_path)
