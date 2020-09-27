import socket

import client_storage
from common import crypt
from common.socket_util import Socket, PLAIN_TEXT, AES_ENCODED, decode_utf8, NO_INPUT, SUCCESS, REFRESH


class Client:
    def __init__(self, address: str, port: int):
        self.aes_key = None
        self.address = address
        self.port = port
        self.sock = None

    def start(self):
        if not client_storage.check_rsa():
            print("There is no RSA key. Generating RSA...")
            client_storage.gen_rsa()
        else:
            print("RSA key was found. Do you want to override it? (y/n)")
            if input().lower() == 'y':
                client_storage.gen_rsa()
        self.sock = Socket(socket.create_connection((self.address, self.port)))
        if self.auth(is_first=True):
            self.receive_loop()

    def receive_loop(self):
        from client_command import perform_by_name

        while True:
            response = self.sock.recv()
            if response.response_code == REFRESH:
                self.auth()
                continue
            if response.response_code != SUCCESS:
                print(decode_utf8(response.body))
                print("Response code: {}".format(response.response_code))
                continue
            if response.encoded_flag == PLAIN_TEXT:
                if response.body[0] == 33:
                    perform_by_name(response.body, self)
                    continue
                else:
                    print(decode_utf8(response.body))
            elif response.encoded_flag == AES_ENCODED:
                print(decode_utf8(crypt.decrypt_aes(self.aes_key, response.body)))
            else:
                print(response.body)
            if response.input_wanted_flag == NO_INPUT:
                continue
            self.sock.send_string(input())

    def auth(self, is_first=False):
        if is_first:
            print(decode_utf8(self.sock.recv().body))
            username = input()
            self.sock.send_string(username)
        print(decode_utf8(self.sock.recv().body))
        password = input()
        self.sock.send_string(password)
        response = self.sock.recv()
        if response.response_code != SUCCESS:
            print("Failed to authenticate. Response code: {}".format(response.response_code))
            self.sock.close()
            return False
        pub, private = client_storage.get_rsa_pair()
        if is_first:
            self.sock.send(pub)
        aes_key_coded = self.sock.recv().body
        self.aes_key = crypt.decrypt_rsa(private, aes_key_coded)
        return True


if __name__ == '__main__':
    Client('127.0.0.1', 8080).start()
