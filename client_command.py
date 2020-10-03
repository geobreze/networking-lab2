from client import Client
from client_storage import edit_file
from common.crypt import encrypt_aes, decrypt_aes
from common.socket_util import AES_ENCODED, NO_INPUT, decode_utf8


def perform_by_name(command: bytes, client: Client):
    sp = command.split(b'-||-')
    name = sp[0]
    args = sp[1:]
    if name == b'!editor':
        edit_file_command(client, *args)


def edit_file_command(client: Client, name: bytes, initial_data):
    i_data = b''
    if initial_data != b'':
        i_data = decrypt_aes(client.aes_key, initial_data)
    data = edit_file(decode_utf8(name) + '.swap', initial_data=i_data)
    encrypted = encrypt_aes(client.aes_key, data)
    client.sock.send(encrypted, flag=AES_ENCODED, input_wanted=NO_INPUT)
