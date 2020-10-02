import datetime
import os
import socket
import threading

import storage
from common import crypt
from common.crypt import decrypt_aes
from common.socket_util import Socket, decode_utf8, FORBIDDEN, NO_INPUT, BAD_REQUEST, SUCCESS, REFRESH


class Server:
    def __init__(self, host, port, backlog=10):
        self.sessions = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(backlog)

    def accept(self):
        while True:
            (client_socket, remote_addr) = self.sock.accept()
            session = Session(Socket(client_socket), remote_addr)
            self.sessions.append(session)
            t = threading.Thread(target=session.handle_request)
            t.start()


class Session:
    def __init__(self, client_socket: Socket, remote_addr, token_timeout=datetime.timedelta(minutes=1)):
        self.sock = client_socket
        self.addr = remote_addr
        self.username = None
        self.key = None
        self.last_token_update = datetime.datetime.now()
        self.token_timeout = token_timeout
        self.rsa_pub = None

    def handle_request(self):
        from command import perform_by_name

        self.authenticate(is_first=True)
        while True:
            self.refresh_token()
            self.sock.send_string("Please, enter command.")
            cmd = decode_utf8(self.sock.recv().body)
            try:
                perform_by_name(cmd, self)
            except NameError as e:
                print(e)
                self.sock.send_string("Invalid name was supplied. Try again.", input_wanted=NO_INPUT,
                                      response_code=BAD_REQUEST)
            except PermissionError:
                print("Permission denied for user {}.".format(self.username))
                self.sock.send_string("Permission denied.", input_wanted=NO_INPUT,
                                      response_code=FORBIDDEN)

    def authenticate(self, is_first=False):
        if is_first:
            self.rsa_pub = self.sock.recv().body

        self.key = os.urandom(16)
        encoded_key = crypt.encrypt_rsa(self.rsa_pub, self.key)
        self.sock.send(encoded_key)
        self.last_token_update = datetime.datetime.now()

        if is_first:
            self.sock.send_string("Enter login:")
            self.username = decode_utf8(self.sock.recv().body)
        print("{} trying to authenticate".format(self.username))
        self.sock.send_string("Enter password:")
        password = decrypt_aes(self.key, self.sock.recv().body)
        if not storage.authenticate(self.username, password):
            print("Invalid login {} supplied. Closing the socket.".format(self.username))
            self.sock.send(b'', input_wanted=NO_INPUT, response_code=FORBIDDEN)
            self.sock.close()
            return
        self.sock.send(b'', input_wanted=NO_INPUT, response_code=SUCCESS)

    def refresh_token(self):
        if datetime.datetime.now() < self.token_timeout + self.last_token_update:
            return
        self.sock.send(b'', response_code=REFRESH)
        self.authenticate()


if __name__ == '__main__':
    Server('0.0.0.0', 8080).accept()
