import socket
import aes
import ecc
import socket_helper
import crypto_helper

# Server information
server_ip = 'localhost'
server_port = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, server_port))

print("Hello From Bob:")

# Receive the ECC parameters and Alice's public key from Alice
a, b, x, y, p, key_size, pub_key = socket_helper.receive_ecc_params(
    client_socket)
print("Parameters Received From Alice:\n" + "a = " + str(a) + "\nb = " + str(b) + "\nx = " +
      str(x) + "\ny = " + str(y) + "\np = " + str(p) + "\nKey Size = " + str(key_size))
print("Alice's Public Key: " + str(pub_key))

# Compute own public and private keys
my_private_key, my_public_key = ecc.generate_keys((x, y), a, b, p, key_size)

# Send the public key to Alice
client_socket.send(
    (str(my_public_key[0]) + "," + str(my_public_key[1])).encode())

# Compute the shared secret key
shared_secret_key = ecc.generate_shared_secret_key(
    pub_key, my_private_key, a, b, p)
print("Shared Secret Key: " + str(shared_secret_key))
key_byte_array = crypto_helper.int_to_bytes(shared_secret_key[0])
AES_key = crypto_helper.fix_key(key_byte_array, key_size)


# Hear ready from Alice
reply = client_socket.recv(1024).decode()
if reply == "ready":
    print("Alice is ready for communication.")
    # Say ready to Alice
    client_socket.send("ready".encode())
else:
    print("Alice is not ready for communication.")
    exit(0)

while True:
    msg_type = client_socket.recv(1024).decode()

    if msg_type == "text":
        text = socket_helper.receive_text_message(
            client_socket, AES_key, key_size)
        print("Alice: " + text)
    elif msg_type == "file":
        pass
    elif msg_type == "bye":
        print("Alice has left the chat.")
        client_socket.close()
        exit(0)
    else:
        print("Unknown message type received.")
        exit(0)
