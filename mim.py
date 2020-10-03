import socket
import threading

from common import crypt
from common.socket_util import Socket, REFRESH, AES_ENCODED, INPUT_WANTED


class MIMServer:
    def __init__(self, host, port, s_host, s_port, backlog=10):
        self.sessions = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(backlog)
        self.s_host = s_host
        self.s_port = s_port
        self.s_sock = Socket(socket.create_connection((self.s_host, self.s_port)))

    def accept(self):
        while True:
            (client_socket, remote_addr) = self.sock.accept()
            session = MIMSession(Socket(client_socket), self.s_sock)
            self.sessions.append(session)
            t = threading.Thread(target=session.handle_request)
            t.start()


class MIMSession:
    def __init__(self, client_socket: Socket, server_socket: Socket):
        self.sock = client_socket
        self.s_sock = server_socket
        self.key = None
        self.client_rsa_pub = None
        self.rsa_pub, self.rsa_pri = crypt.generate_rsa_keypair()

    def handle_request(self):
        self.authenticate(is_first=True)
        c_input_wanted_flag = INPUT_WANTED
        s_input_wanted_flag = INPUT_WANTED
        while True:
            if c_input_wanted_flag:
                s_response = self.printing_replicate_from_server()
                s_input_wanted_flag = s_response.input_wanted_flag
                if s_response.response_code == REFRESH:
                    self.authenticate()
                    continue
            if s_input_wanted_flag == INPUT_WANTED:
                c_response = self.printing_replicate_from_client()
                c_input_wanted_flag = c_response.input_wanted_flag

    def authenticate(self, is_first=False):
        if is_first:
            response = self.sock.recv()
            self.client_rsa_pub = response.body
            self.s_sock.send(self.rsa_pub)

        encoded_key = self.s_sock.recv().body
        self.key = crypt.decrypt_rsa(self.rsa_pri, encoded_key)
        encoded_for_client_key = crypt.encrypt_rsa(self.client_rsa_pub, self.key)
        self.sock.send(encoded_for_client_key)

        if is_first:
            self.printing_replicate_from_server()
            self.printing_replicate_from_client()
        self.printing_replicate_from_server()
        self.printing_replicate_from_client()
        self.printing_replicate_from_server()

    def printing_replicate_from_client(self):
        response = self.sock.recv()
        print(response.body)
        if response.encoded_flag == AES_ENCODED:
            print(crypt.decrypt_aes(self.key, response.body))
        self.s_sock.send(response.body, flag=response.encoded_flag, input_wanted=response.input_wanted_flag,
                         response_code=response.response_code)
        return response

    def printing_replicate_from_server(self):
        response = self.s_sock.recv()
        print(response.body)
        if response.encoded_flag == AES_ENCODED:
            print(crypt.decrypt_aes(self.key, response.body))
        self.sock.send(response.body, flag=response.encoded_flag, input_wanted=response.input_wanted_flag,
                       response_code=response.response_code)
        return response


if __name__ == '__main__':
    MIMServer('0.0.0.0', 8080, '127.0.0.1', 8081).accept()
