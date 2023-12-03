import crypto_helper

def send_ecc_params(a, b, x, y, p, key_size, pub_key, socket):
    params = str(a) + "|" + str(b) + "|" + str(x) + "|" + str(y) + "|" + str(p) + "|" + str(key_size) + "|" + str(pub_key[0]) + "," + str(pub_key[1])
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
    encrypted_text = crypto_helper.encrypt(text, key, iv, key_size)
    socket.send(encrypted_text.encode())
    
def receive_text_message(socket, key, key_size):
    encrypted_text = socket.recv(8192).decode()
    text = crypto_helper.decrypt(encrypted_text, key, key_size)
    return text