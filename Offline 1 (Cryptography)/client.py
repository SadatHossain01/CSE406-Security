import socket
import aes
import ecc

# Server information
server_ip = 'localhost'
server_port = 12345


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, server_port))

params = client_socket.recv(8192).decode()
print("Hello From Bob:")
print("Parameters Received From Alice:\n" + params)

stuffs = params.split('\n')
a = int(stuffs[0][3:])
b = int(stuffs[1][3:])
x = int(stuffs[2][3:])
y = int(stuffs[3][3:])
p = int(stuffs[4][3:])
key_size = int(stuffs[5][3:])
initialization_vector = stuffs[6][4:]
# print(a, b, x, y, p, initialization_vector)

# Receive Alice's public key
other_public_key = client_socket.recv(8192).decode()
print("Alice's Public Key: " + str(other_public_key))

other_pub_x = int(other_public_key.split(',')[0])
other_pub_y = int(other_public_key.split(',')[1])

# Compute and send the public key to Alice
my_private_key, my_public_key = ecc.generate_keys((x, y), a, b, p, key_size)
msg = str(my_public_key[0]) + "," + str(my_public_key[1])
client_socket.send(msg.encode())

shared_secret_key = ecc.generate_shared_secret_key(
    (other_pub_x, other_pub_y), my_private_key, a, b, p)
print("Shared Secret Key: " + str(shared_secret_key))

key = str(shared_secret_key[0])

msg = client_socket.recv(8192).decode()
print("Encrypted Message Received: " + msg)
decrypted_msg = aes.decrypt(msg, key, initialization_vector, key_size)
print("Decrypted Message: " + decrypted_msg)

client_socket.close()
