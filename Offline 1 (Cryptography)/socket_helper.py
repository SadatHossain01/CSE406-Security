import aes
import crypto_helper
import numpy as np


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

    # First send a "file" string to indicate that the message is a file
    socket.send("file".encode())
    # Then send the file name
    socket.send(file_path.encode())
    iv = crypto_helper.generate_iv()

    data = bytearray(file_data)
    encrypted_data = aes.encrypt(
        data, key, iv, key_size)
    socket.send(iv.tobytes() + encrypted_data.tobytes())

    print("File sent.")


def receive_file(socket, key, key_size):
    # First receive the file name
    file_name = socket.recv(8192).decode()
    print("File name: " + file_name)

    # Then receive the file data
    data = bytes([])
    buffer = socket.recv(8192)
    data += buffer
    # while buffer:
    #     data += buffer
    #     buffer = socket.recv(8192)

    print("Encrypted data length: " + str(len(data)) + "bytes")

    iv = data[:16]
    encrypted_data = data[16:]
    decrypted_data = aes.decrypt(encrypted_data, key, iv, key_size)

    print("Decrypted data length: " + str(len(decrypted_data)) + "bytes")

    # write this byte array to a new file
    final_bytes = decrypted_data.tobytes()
    new_path = "new_" + file_name
    with open(new_path, 'wb') as file:
        file.write(final_bytes)
    print("File received and saved to " + new_path)
