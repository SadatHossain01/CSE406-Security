import socket
import ecc
import socket_helper
import crypto_helper

# Server information
server_ip = 'localhost'
server_port = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 12345)
server_socket.bind(server_address)


server_socket.listen(1)

client_socket, client_address = server_socket.accept()


print("Hello From Alice:")
key_size = int(input("Choose AES key size (128, 192, 256): "))

# Generate the ECC parameters
a, b, x, y, p = ecc.generate_ecc_curve_params(key_size)

# Compute own public and private keys
my_private_key, my_public_key = ecc.generate_keys((x, y), a, b, p, key_size)

# Send the ECC parameters and public key to Bob
socket_helper.send_ecc_params(
    a, b, x, y, p, key_size, my_public_key, client_socket)

# Receive Bob's public key
other_public_key = client_socket.recv(8192).decode()
print("Bob's Public Key: " + str(other_public_key))
other_pub_x = int(other_public_key.split(',')[0])
other_pub_y = int(other_public_key.split(',')[1])

# Compute the shared secret key
shared_secret_key = ecc.generate_shared_secret_key(
    (other_pub_x, other_pub_y), my_private_key, a, b, p)
print("Shared Secret Key: " + str(shared_secret_key))
key_byte_array = crypto_helper.int_to_bytes(shared_secret_key[0])
AES_key = crypto_helper.fix_key(key_byte_array, key_size)

# Say ready to Bob
client_socket.send("ready".encode())

# Hear ready from Bob
reply = client_socket.recv(1024).decode()
if reply == "ready":
    print("Bob is ready to for communication.")
else:
    print("Bob is not ready to for communication.")
    exit(0)
    
while True:
    choice = int(input("What do you want to send to Bob? (1. Text, 2. File): "))
    
    if choice == 1:
        message = input("Enter message: ")
        socket_helper.send_text_message(message, client_socket, AES_key, key_size)
    else:
        pass