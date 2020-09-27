import socket

LEN_LENGTH = 4
FLAG_LENGTH = 1
INPUT_FLAG_LENGTH = 1
RESPONSE_CODE_LENGTH = 1

PLAIN_TEXT = int.to_bytes(0x00, FLAG_LENGTH, byteorder='big', signed=False)
AES_ENCODED = int.to_bytes(0x01, FLAG_LENGTH, byteorder='big', signed=False)
RSA_ENCODED = int.to_bytes(0x02, FLAG_LENGTH, byteorder='big', signed=False)

INPUT_WANTED = int.to_bytes(0x00, INPUT_FLAG_LENGTH, byteorder='big', signed=False)
NO_INPUT = int.to_bytes(0x01, INPUT_FLAG_LENGTH, byteorder='big', signed=False)

SUCCESS = int.to_bytes(0x00, RESPONSE_CODE_LENGTH, byteorder='big', signed=False)
FORBIDDEN = int.to_bytes(0x01, RESPONSE_CODE_LENGTH, byteorder='big', signed=False)
UNKNOWN_ERROR = int.to_bytes(0x02, RESPONSE_CODE_LENGTH, byteorder='big', signed=False)
BAD_REQUEST = int.to_bytes(0x03, RESPONSE_CODE_LENGTH, byteorder='big', signed=False)


class Response:
    def __init__(self, body, encoded_flag, input_wanted_flag, response_code):
        self.body = body
        self.encoded_flag = encoded_flag
        self.input_wanted_flag = input_wanted_flag
        self.response_code = response_code


class Socket:
    def __init__(self, s: socket.socket):
        self.s = s

    def send(self, data: bytes, flag=PLAIN_TEXT, input_wanted=INPUT_WANTED, response_code=SUCCESS):
        length = len(data)
        self.s.send(int.to_bytes(length, length=LEN_LENGTH, byteorder='big', signed=False))
        self.s.send(flag)
        self.s.send(input_wanted)
        self.s.send(response_code)
        self.s.send(data)

    def send_string(self, data: str, input_wanted=INPUT_WANTED, response_code=SUCCESS):
        self.send(encode_utf8(data), input_wanted=input_wanted, response_code=response_code)

    def recv(self):
        length = int.from_bytes(self.s.recv(LEN_LENGTH), byteorder='big', signed=False)
        flag = self.s.recv(FLAG_LENGTH)
        input_wanted = self.s.recv(INPUT_FLAG_LENGTH)
        response_code = self.s.recv(RESPONSE_CODE_LENGTH)
        return Response(body=self.s.recv(length), encoded_flag=flag, input_wanted_flag=input_wanted,
                        response_code=response_code)

    def close(self):
        return self.s.close()


def encode_utf8(data: str) -> bytes:
    return data.encode('utf-8')


def decode_utf8(data: bytes) -> str:
    return data.decode('utf-8')
