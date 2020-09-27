import storage
from common.crypt import encrypt_aes, decrypt_aes
from common.socket_util import decode_utf8, AES_ENCODED, NO_INPUT, UNKNOWN_ERROR
from server import Session

storage_path = 'storage/'


def perform_by_name(name: str, session: Session):
    if name == 'get':
        perform_get(session)
    elif name == 'new':
        perform_new(session)
    elif name == 'edit':
        perform_edit(session)
    elif name == 'delete':
        perform_delete(session)
    else:
        raise NameError("Invalid name supplied")


def perform_get(session: Session):
    session.sock.send_string("Please, enter filename to read.")
    file = decode_utf8(session.sock.recv().body)
    try:
        data = storage.get_for_user(session.username, file)
        enc = encrypt_aes(session.key, data)
        session.sock.send(enc, flag=AES_ENCODED, input_wanted=NO_INPUT)
    except:
        session.sock.send(b'Unknown error occurred during get processing', input_wanted=NO_INPUT,
                          response_code=UNKNOWN_ERROR)


def perform_new(session: Session):
    session.sock.send_string("Please, enter filename to create.")
    file = decode_utf8(session.sock.recv().body)
    session.sock.send_string("!editor file ")
    raw = session.sock.recv().body
    try:
        data = decrypt_aes(session.key, raw)
        storage.create_for_user(session.username, file, data)
    except:
        session.sock.send(b'Unknown error occurred during get processing', input_wanted=NO_INPUT,
                          response_code=UNKNOWN_ERROR)


def perform_edit(session: Session):
    session.sock.send_string("Please, enter filename to edit.")
    file = decode_utf8(session.sock.recv().body)
    try:
        contents = storage.get_for_user(session.username, file)
        session.sock.send("!editor {} ".format(session.username).encode('utf-8') + encrypt_aes(session.key, contents))
        raw = session.sock.recv().body
        data = decrypt_aes(session.key, raw)
        storage.create_for_user(session.username, file, data)
    except:
        session.sock.send(b'Unknown error occurred during get processing', input_wanted=NO_INPUT,
                          response_code=UNKNOWN_ERROR)

def perform_delete(session: Session):
    session.sock.send_string("Please, enter filename to delete.")
    file = decode_utf8(session.sock.recv().body)
    try:
        storage.delete_for_user(session.username, file)
    except:
        session.sock.send(b'Unknown error occurred during get processing', input_wanted=NO_INPUT,
                          response_code=UNKNOWN_ERROR)