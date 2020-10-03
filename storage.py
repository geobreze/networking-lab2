import hashlib
import os
import re
from common import crypt

STORAGE_PATH = 'storage'
PASSWD_PATH = '.passwd'


def assert_system_file(file: str):
    if file.find("..") != -1:
        raise PermissionError
    if re.match(r'/*\.', file) is not None:
        raise PermissionError


def get_for_user(user: str, file: str, key: bytes) -> bytes:
    assert_system_file(file)

    f = open(STORAGE_PATH + '/' + user + '/' + file, 'rb')
    data = f.read()
    f.close()
    return crypt.decrypt_aes(key, data)


def create_for_user(user: str, file: str, data: bytes, key: bytes):
    assert_system_file(file)

    f = open(STORAGE_PATH + '/' + user + '/' + file, 'wb')
    f.write(crypt.encrypt_aes(key, data))
    f.close()


def delete_for_user(user: str, file: str):
    assert_system_file(file)

    os.remove(STORAGE_PATH + '/' + user + '/' + file)


def authenticate(user: str, passwd: bytes):
    for registered_user in os.listdir(STORAGE_PATH):
        if registered_user == user:
            passwd_f = open(STORAGE_PATH + '/' + user + '/' + PASSWD_PATH, 'r', encoding='utf-8')
            stored_passwd_hash = passwd_f.read()
            passwd_f.close()
            return stored_passwd_hash == hashlib.sha256(passwd).hexdigest()
    return False
