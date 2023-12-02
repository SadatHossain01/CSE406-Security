import socket
import aes
import ecc
import random

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 12345)
server_socket.bind(server_address)


server_socket.listen(1)

client_socket, client_address = server_socket.accept()


# Send initializing parameters
print("Hello From Alice:")
key_size = int(input("Choose AES key size (128, 192, 256): "))

a, b, x, y, p = ecc.generate_ecc_curve_params(key_size)
# generate the IV
initialization_vector = ""
for i in range(16):
    initialization_vector += chr(random.randint(0, 255))

params = "a: " + str(a) + "\n" + "b: " + str(b) + "\n" + "x: " + \
    str(x) + "\n" + "y: " + str(y) + "\n" + "p: " + str(p) + "\n" + \
    "sz: " + str(key_size) + "\n" + "IV: " + str(initialization_vector)

client_socket.send(params.encode())

my_private_key, my_public_key = ecc.generate_keys((x, y), a, b, p, key_size)

# Send the public key to Bob
msg = str(my_public_key[0]) + "," + str(my_public_key[1])
client_socket.send(msg.encode())

other_public_key = client_socket.recv(8192).decode()
print("Bob's Public Key: " + str(other_public_key))

other_pub_x = int(other_public_key.split(',')[0])
other_pub_y = int(other_public_key.split(',')[1])

shared_secret_key = ecc.generate_shared_secret_key(
    (other_pub_x, other_pub_y), my_private_key, a, b, p)
print("Shared Secret Key: " + str(shared_secret_key))

key = str(shared_secret_key[0])

choice = int(input("What do you want to send to Bob? (1: Text, 2: File): "))

if choice == 1:
    msg = input("Enter your message: ")
    encrypted_msg = aes.encrypt(msg, key, initialization_vector, key_size)
    client_socket.send(encrypted_msg.encode())

client_socket.close()

server_socket.close()
