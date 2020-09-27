import os
import socket
import threading

import storage
from common import crypt
from common.socket_util import Socket, decode_utf8, FORBIDDEN, NO_INPUT, BAD_REQUEST, SUCCESS


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
    def __init__(self, client_socket: Socket, remote_addr):
        self.sock = client_socket
        self.addr = remote_addr
        self.username = ""
        self.key = os.urandom(16)

    def handle_request(self):
        from command import perform_by_name

        self.sock.send_string("Enter login:")
        self.username = decode_utf8(self.sock.recv().body)
        print("{} trying to authenticate".format(self.username))
        self.sock.send_string("Enter password:")
        password = self.sock.recv().body
        if not storage.authenticate(self.username, password):
            print("Invalid login {} supplied. Closing the socket.".format(self.username))
            self.sock.send(b'', input_wanted=NO_INPUT, response_code=FORBIDDEN)
            self.sock.close()
            return
        self.sock.send(b'', input_wanted=NO_INPUT, response_code=SUCCESS)
        rsa_pub = self.sock.recv().body
        encoded_key = crypt.encrypt_rsa(rsa_pub, self.key)
        self.sock.send(encoded_key)
        while True:
            self.sock.send_string("Please, enter command.")
            cmd = decode_utf8(self.sock.recv().body)
            try:
                perform_by_name(cmd, self)
            except NameError:
                print("Invalid name was supplied.")
                self.sock.send_string("Invalid name was supplied. Try again.", input_wanted=NO_INPUT,
                                      response_code=BAD_REQUEST)
            except PermissionError:
                print("Permission denied for user {}.".format(self.username))
                self.sock.send_string("Permission denied.", input_wanted=NO_INPUT,
                                      response_code=FORBIDDEN)


if __name__ == '__main__':
    Server('0.0.0.0', 8080).accept()
