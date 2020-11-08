import socket
import os.path
from _thread import *
import random
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import time

ServerSocket = socket.socket()
host = '127.0.0.1'
port = 1233
ThreadCount = 0
K1 = os.urandom(16)
K2 = os.urandom(16)
K3 = os.urandom(16)
IV = os.urandom(16)
file = open("ThirdKey.txt", "wb")
file.write(K3)
file.close()

try:
    ServerSocket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waiting for a Connection..')
ServerSocket.listen(5)

salt = b'salt_'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(K3))


def encrypt_data(byte_msg):
    f = Fernet(key)
    encrypted = f.encrypt(byte_msg)
    return encrypted


def decript_data(byte_msg):
    f = Fernet(key)
    decrypt = f.decrypt(byte_msg)
    decrypt = decrypt.decode()
    return decrypt


def threaded_client(connection):
    connection.send(str.encode('Welcome to the Server\n'))
    while True:
        data = connection.recv(2048)
        time.sleep(10)

        file1 = open("Responses.txt", "a")
        file1.write(data.decode('utf-8') + '\n')
        file1.close()

        file1 = open('Responses.txt', 'r')
        Lines = file1.readlines()

        mode = ''
        lenght = len(Lines)
        if lenght == 2:
            if Lines[lenght - 1] == Lines[lenght - 2]:
                mode = Lines[lenght - 1]
            else:
                randomNumber = random.randrange(1, 3)
                mode = Lines[lenght - randomNumber]
            file1 = open("Responses.txt", "w")
            file1.close()
        reply = 'Waiting for both parties to express their option'
        if len(mode) > 0:
            if mode == 'ECB\n':
                data_to_send = encrypt_data(K1).decode('utf-8')
                reply = 'Associated key:' + data_to_send
            else:
                data_to_send = encrypt_data(K2).decode('utf-8')
                init_vector = encrypt_data(IV).decode('utf-8')
                reply = 'Associated key:' + data_to_send + 'initialization array:' + init_vector

        if not data:
            break
        connection.sendall(str.encode(reply))
    # connection.close()


while True:
    Client, address = ServerSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(threaded_client, (Client,))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))

# ServerSocket.close()
